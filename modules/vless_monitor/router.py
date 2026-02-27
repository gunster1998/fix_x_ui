"""
vless_monitor — проверяет доступность VLESS-портов со стороны клиента.

Каждые 5 минут подключается по SSH к домашнему серверу (обычный интернет)
и оттуда делает TCP-проверку VLESS-портов всех включённых серверов.
При недоступности (FAIL_THRESHOLD провалов подряд) отправляет уведомление
администраторам. При восстановлении — уведомление о recovery.
"""

import asyncio
import json
import httpx
import asyncssh

from urllib.parse import urlparse
from aiogram import F, Router
from aiogram.types import CallbackQuery, InlineKeyboardButton
from aiogram.utils.keyboard import InlineKeyboardBuilder

from filters.admin import IsAdminFilter
from handlers.admin.panel.keyboard import AdminPanelCallback
from hooks.hooks import register_hook
from logger import logger

router = Router(name="vless_monitor")

_monitor_task: asyncio.Task | None = None
_fail_counts: dict[str, int] = {}   # server_name -> consecutive fails
_down_servers: set[str] = set()     # servers currently marked as down


async def _run_checks(bot):
    from .settings import (
        HOME_SSH_HOST, HOME_SSH_PORT, HOME_SSH_USER, HOME_SSH_PASS,
        FAIL_THRESHOLD, CONNECT_TIMEOUT,
    )
    from database import async_session_maker, get_servers
    from panels._3xui import get_xui_instance
    from config import ADMIN_ID

    try:
        async with async_session_maker() as session:
            servers_dict = await get_servers(session, include_enabled=True)
    except Exception as e:
        logger.warning(f"[vless_monitor] Ошибка получения серверов: {e}")
        return

    # Собираем цели: server_name -> (host, port)
    targets: dict[str, tuple[str, int]] = {}

    for cluster_id, server_list in servers_dict.items():
        for server_info in server_list:
            if server_info.get("panel_type", "3x-ui") != "3x-ui":
                continue

            api_url = server_info.get("api_url")
            inbound_id = server_info.get("inbound_id")
            server_name = server_info.get("server_name", "unknown")

            if not api_url or not inbound_id:
                continue

            try:
                xui = await get_xui_instance(api_url)
                host = xui.inbound._host
                session_cookie = xui._session or xui.inbound._session
                port = await _get_inbound_port(host, session_cookie, int(inbound_id))
                if port:
                    parsed = urlparse(api_url)
                    vless_host = parsed.hostname
                    targets[server_name] = (vless_host, port)
            except Exception as e:
                logger.warning(f"[vless_monitor] {server_name}: ошибка получения порта: {e}")

    if not targets:
        logger.warning("[vless_monitor] Нет серверов для проверки")
        return

    logger.warning(f"[vless_monitor] Проверяю {len(targets)} серверов с домашнего интернета")

    # Запускаем проверки с домашнего сервера
    results = await _check_from_home(
        targets=targets,
        ssh_host=HOME_SSH_HOST,
        ssh_port=HOME_SSH_PORT,
        ssh_user=HOME_SSH_USER,
        ssh_pass=HOME_SSH_PASS,
        timeout=CONNECT_TIMEOUT,
    )

    if not results:
        logger.warning("[vless_monitor] SSH к домашнему серверу недоступен, пропускаю")
        return

    # Обрабатываем результаты
    up_count = sum(1 for ok in results.values() if ok)
    down_count = len(results) - up_count
    logger.warning(
        f"[vless_monitor] Результат: {up_count} ✅ / {down_count} ❌ из {len(results)} серверов"
    )

    for server_name, ok in results.items():
        if ok:
            if server_name in _down_servers:
                _down_servers.discard(server_name)
                _fail_counts[server_name] = 0
                host, port = targets[server_name]
                logger.warning(f"[vless_monitor] ✅ {server_name} ({host}:{port}) восстановлен")
                for admin in ADMIN_ID:
                    try:
                        await bot.send_message(
                            admin,
                            f"✅ Сервер <b>{server_name}</b> снова доступен\n"
                            f"<code>{host}:{port}</code>",
                            parse_mode="HTML",
                        )
                    except Exception:
                        pass
            else:
                _fail_counts[server_name] = 0
        else:
            count = _fail_counts.get(server_name, 0) + 1
            _fail_counts[server_name] = count
            host, port = targets[server_name]
            logger.warning(
                f"[vless_monitor] ❌ {server_name} ({host}:{port}) недоступен, провал #{count}"
            )

            if count >= FAIL_THRESHOLD and server_name not in _down_servers:
                _down_servers.add(server_name)
                for admin in ADMIN_ID:
                    try:
                        await bot.send_message(
                            admin,
                            f"❌ Сервер <b>{server_name}</b> недоступен!\n"
                            f"<code>{host}:{port}</code> не отвечает\n"
                            f"Проверка со стороны клиента (домашний интернет)",
                            parse_mode="HTML",
                        )
                    except Exception:
                        pass


async def _get_inbound_port(host: str, session_cookie: str, inbound_id: int) -> int | None:
    """Получает порт VLESS-inbound через x-ui API."""
    cookies = {"3x-ui": session_cookie}
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(cookies=cookies, verify=False, timeout=10) as client:
            resp = await client.get(f"{base}/panel/api/inbounds/get/{inbound_id}")
            data = resp.json()
            if data.get("success"):
                return data.get("obj", {}).get("port")
    except Exception as e:
        logger.warning(f"[vless_monitor] Ошибка получения inbound порта: {e}")
    return None


async def _check_from_home(
    targets: dict[str, tuple[str, int]],
    ssh_host: str,
    ssh_port: int,
    ssh_user: str,
    ssh_pass: str,
    timeout: int,
) -> dict[str, bool]:
    """SSH на домашний сервер → TCP-проверка всех VLESS-портов."""
    # Скрипт выполняется на домашнем сервере, возвращает JSON с результатами
    checks_json = json.dumps({name: list(hp) for name, hp in targets.items()})
    # Параллельные проверки через ThreadPoolExecutor — все сразу, результат за timeout+2 сек
    script = (
        "import socket, json, concurrent.futures\n"
        f"targets = {checks_json}\n"
        "def check(item):\n"
        "    name, (host, port) = item\n"
        "    try:\n"
        f"        s = socket.create_connection((host, port), timeout={timeout})\n"
        "        s.close()\n"
        "        return name, True\n"
        "    except Exception:\n"
        "        return name, False\n"
        "with concurrent.futures.ThreadPoolExecutor() as ex:\n"
        "    results = dict(ex.map(check, targets.items()))\n"
        "print(json.dumps(results))\n"
    )
    # Максимальное время SSH-сессии: коннект(15) + выполнение(timeout+15)
    ssh_timeout = timeout + 30

    async def _do_ssh():
        async with asyncssh.connect(
            host=ssh_host,
            port=ssh_port,
            username=ssh_user,
            password=ssh_pass,
            known_hosts=None,
            connect_timeout=15,
        ) as conn:
            result = await conn.run("python3 -", input=script, timeout=ssh_timeout)
            if result.returncode == 0:
                return json.loads(result.stdout.strip())
            else:
                logger.warning(f"[vless_monitor] Скрипт упал: {result.stderr[:200]}")
                return {}

    try:
        return await asyncio.wait_for(_do_ssh(), timeout=ssh_timeout + 20)
    except asyncio.TimeoutError:
        logger.warning("[vless_monitor] Превышен общий таймаут SSH-проверки")
    except Exception as e:
        logger.warning(f"[vless_monitor] SSH к домашнему серверу недоступен: {e}")

    return {}


async def _monitor_loop(bot):
    """Фоновый цикл проверки каждые CHECK_INTERVAL секунд."""
    while True:
        from .settings import CHECK_INTERVAL
        try:
            await _run_checks(bot)
        except Exception as e:
            logger.error(f"[vless_monitor] Ошибка в цикле проверки: {e}")
        await asyncio.sleep(CHECK_INTERVAL)


async def _on_periodic(bot, session, **kwargs):
    """Хук periodic_notifications — запускает фоновый монитор при первом вызове."""
    global _monitor_task
    if _monitor_task is None or _monitor_task.done():
        logger.warning("[vless_monitor] Запуск монитора VLESS (домашний интернет)")
        _monitor_task = asyncio.create_task(_monitor_loop(bot))


register_hook("periodic_notifications", _on_periodic)


# ── Кнопка в админ-панели ─────────────────────────────────────────────────────

@register_hook("admin_panel")
def admin_panel_button(admin_role: str = "admin", **kwargs):
    """Добавляет кнопку 'Проверить VLESS' в админ-панель."""
    btn = InlineKeyboardButton(
        text="🔍 Проверить VLESS",
        callback_data=AdminPanelCallback(action="vless_monitor_check").pack(),
    )
    return {"button": btn}


@router.callback_query(AdminPanelCallback.filter(F.action == "vless_monitor_check"), IsAdminFilter())
async def handle_check_now(callback: CallbackQuery):
    """Ручная проверка VLESS-портов с домашнего сервера."""
    from .settings import HOME_SSH_HOST, HOME_SSH_PORT, HOME_SSH_USER, HOME_SSH_PASS, CONNECT_TIMEOUT
    from panels._3xui import get_xui_instance
    from database import async_session_maker, get_servers

    await callback.answer("Проверяю серверы...", show_alert=False)
    await callback.message.edit_text("🔍 Проверяю доступность VLESS-портов с домашнего интернета...")

    # Собираем цели
    targets: dict[str, tuple[str, int]] = {}
    try:
        async with async_session_maker() as session:
            servers_dict = await get_servers(session, include_enabled=True)

        for cluster_id, server_list in servers_dict.items():
            for server_info in server_list:
                if server_info.get("panel_type", "3x-ui") != "3x-ui":
                    continue
                api_url = server_info.get("api_url")
                inbound_id = server_info.get("inbound_id")
                server_name = server_info.get("server_name", "unknown")
                if not api_url or not inbound_id:
                    continue
                try:
                    xui = await get_xui_instance(api_url)
                    host = xui.inbound._host
                    session_cookie = xui._session or xui.inbound._session
                    port = await _get_inbound_port(host, session_cookie, int(inbound_id))
                    if port:
                        vless_host = urlparse(api_url).hostname
                        targets[server_name] = (vless_host, port)
                except Exception:
                    pass
    except Exception as e:
        await callback.message.edit_text(f"❌ Ошибка получения серверов: {e}")
        return

    if not targets:
        await callback.message.edit_text("❌ Нет серверов для проверки.")
        return

    # Запускаем проверки
    results = await _check_from_home(
        targets=targets,
        ssh_host=HOME_SSH_HOST,
        ssh_port=HOME_SSH_PORT,
        ssh_user=HOME_SSH_USER,
        ssh_pass=HOME_SSH_PASS,
        timeout=CONNECT_TIMEOUT,
    )

    if not results:
        await callback.message.edit_text(
            "⚠️ Не удалось подключиться к домашнему серверу для проверки."
        )
        return

    # Формируем отчёт
    lines = []
    for name in sorted(results.keys()):
        ok = results[name]
        host, port = targets.get(name, ("?", "?"))
        icon = "✅" if ok else "❌"
        lines.append(f"{icon} <b>{name}</b> — <code>{host}:{port}</code>")

    up = sum(1 for ok in results.values() if ok)
    down = len(results) - up
    text = (
        f"🔍 Проверка VLESS-портов (домашний интернет)\n\n"
        + "\n".join(lines)
        + f"\n\n<b>Итого: {up} ✅ / {down} ❌</b>"
    )

    kb = InlineKeyboardBuilder()
    kb.row(InlineKeyboardButton(
        text="🔄 Обновить",
        callback_data=AdminPanelCallback(action="vless_monitor_check").pack(),
    ))
    kb.row(InlineKeyboardButton(
        text="⬅️ Назад",
        callback_data=AdminPanelCallback(action="admin").pack(),
    ))

    await callback.message.edit_text(text, reply_markup=kb.as_markup(), parse_mode="HTML")
