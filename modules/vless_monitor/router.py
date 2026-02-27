"""
vless_monitor — проверяет доступность VLESS-подписок со стороны клиента.

Каждые 5 минут подключается по SSH к домашнему серверу (обычный интернет),
оттуда скачивает реальную подписку каждого сервера и проверяет, что в ответе
есть vless:// ссылки. Это тестирует и x-ui subscription-сервер, и xray целиком.

При недоступности (≥ FAIL_THRESHOLD провалов подряд) — уведомление администраторам.
При восстановлении — уведомление о recovery.
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


# ── Сбор информации о серверах ────────────────────────────────────────────────

async def _get_inbound_sub_url(
    host: str,
    session_cookie: str,
    inbound_id: int,
    subscription_url: str,
) -> str | None:
    """
    Возвращает полный URL подписки для первого клиента inbound-а:
    {subscription_url}/{subId}
    """
    cookies = {"3x-ui": session_cookie}
    base = host.rstrip("/")
    try:
        async with httpx.AsyncClient(cookies=cookies, verify=False, timeout=10) as client:
            resp = await client.get(f"{base}/panel/api/inbounds/get/{inbound_id}")
            data = resp.json()
            if not data.get("success"):
                return None
            obj = data.get("obj", {})
            settings = obj.get("settings", "{}")
            if isinstance(settings, str):
                settings = json.loads(settings)
            clients = settings.get("clients", [])
            if not clients:
                return None
            sub_id = clients[0].get("subId", "")
            if not sub_id:
                return None
            return f"{subscription_url.rstrip('/')}/{sub_id}"
    except Exception as e:
        logger.warning(f"[vless_monitor] Ошибка получения subId: {e}")
    return None


async def _collect_targets(servers_dict: dict) -> dict[str, str]:
    """
    Возвращает {server_name: subscription_url_with_sub_id} для всех включённых серверов.
    """
    from panels._3xui import get_xui_instance

    targets: dict[str, str] = {}
    for cluster_id, server_list in servers_dict.items():
        for server_info in server_list:
            if server_info.get("panel_type", "3x-ui") != "3x-ui":
                continue

            api_url = server_info.get("api_url")
            inbound_id = server_info.get("inbound_id")
            subscription_url = server_info.get("subscription_url", "")
            server_name = server_info.get("server_name", "unknown")

            if not api_url or not inbound_id or not subscription_url:
                continue

            try:
                xui = await get_xui_instance(api_url)
                host = xui.inbound._host
                session_cookie = xui._session or xui.inbound._session
                full_url = await _get_inbound_sub_url(
                    host, session_cookie, int(inbound_id), subscription_url
                )
                if full_url:
                    targets[server_name] = full_url
            except Exception as e:
                logger.warning(f"[vless_monitor] {server_name}: ошибка получения подписки: {e}")

    return targets


# ── Проверка с домашнего сервера ──────────────────────────────────────────────

async def _check_from_home(
    targets: dict[str, str],
    ssh_host: str,
    ssh_port: int,
    ssh_user: str,
    ssh_pass: str,
    timeout: int,
) -> dict[str, bool]:
    """
    SSH на домашний сервер → скачивает каждую подписку, проверяет наличие vless://.
    Возвращает {server_name: ok}.
    """
    urls_json = json.dumps(targets)
    # Параллельная проверка через ThreadPoolExecutor
    script = (
        "import urllib.request, urllib.error, ssl, json, base64, concurrent.futures\n"
        f"targets = {urls_json}\n"
        "ctx = ssl.create_default_context()\n"
        "ctx.check_hostname = False\n"
        "ctx.verify_mode = ssl.CERT_NONE\n"
        "def check(item):\n"
        "    name, url = item\n"
        "    try:\n"
        f"        req = urllib.request.Request(url, headers={{'User-Agent': 'v2rayN/6.40'}})\n"
        f"        resp = urllib.request.urlopen(req, timeout={timeout}, context=ctx)\n"
        "        raw = resp.read(4096)\n"
        "        text = raw.decode('utf-8', errors='ignore')\n"
        "        if 'vless://' in text:\n"
        "            return name, True\n"
        "        try:\n"
        "            decoded = base64.b64decode(text.strip()).decode('utf-8', errors='ignore')\n"
        "            return name, 'vless://' in decoded\n"
        "        except Exception:\n"
        "            return name, False\n"
        "    except Exception:\n"
        "        return name, False\n"
        "with concurrent.futures.ThreadPoolExecutor() as ex:\n"
        "    results = dict(ex.map(check, targets.items()))\n"
        "print(json.dumps(results))\n"
    )
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


# ── Основной цикл ─────────────────────────────────────────────────────────────

async def _run_checks(bot):
    from .settings import (
        HOME_SSH_HOST, HOME_SSH_PORT, HOME_SSH_USER, HOME_SSH_PASS,
        FAIL_THRESHOLD, CONNECT_TIMEOUT,
    )
    from database import async_session_maker, get_servers
    from config import ADMIN_ID

    try:
        async with async_session_maker() as session:
            servers_dict = await get_servers(session, include_enabled=True)
    except Exception as e:
        logger.warning(f"[vless_monitor] Ошибка получения серверов: {e}")
        return

    targets = await _collect_targets(servers_dict)

    if not targets:
        logger.warning("[vless_monitor] Нет серверов для проверки")
        return

    logger.warning(f"[vless_monitor] Проверяю подписки {len(targets)} серверов")

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
                url = targets[server_name]
                logger.warning(f"[vless_monitor] ✅ {server_name} восстановлен")
                for admin in ADMIN_ID:
                    try:
                        await bot.send_message(
                            admin,
                            f"✅ Сервер <b>{server_name}</b> снова доступен\n"
                            f"Подписка отдаёт vless:// ссылки",
                            parse_mode="HTML",
                        )
                    except Exception:
                        pass
            else:
                _fail_counts[server_name] = 0
        else:
            count = _fail_counts.get(server_name, 0) + 1
            _fail_counts[server_name] = count
            logger.warning(
                f"[vless_monitor] ❌ {server_name} подписка недоступна, провал #{count}"
            )

            if count >= FAIL_THRESHOLD and server_name not in _down_servers:
                _down_servers.add(server_name)
                url = targets[server_name]
                for admin in ADMIN_ID:
                    try:
                        await bot.send_message(
                            admin,
                            f"❌ Сервер <b>{server_name}</b> — подписка не работает!\n"
                            f"<code>{url}</code>\n"
                            f"Не возвращает vless:// ссылки (проверка с домашнего интернета)",
                            parse_mode="HTML",
                        )
                    except Exception:
                        pass


async def _monitor_loop(bot):
    while True:
        from .settings import CHECK_INTERVAL
        try:
            await _run_checks(bot)
        except Exception as e:
            logger.error(f"[vless_monitor] Ошибка в цикле проверки: {e}")
        await asyncio.sleep(CHECK_INTERVAL)


async def _on_periodic(bot, session, **kwargs):
    global _monitor_task
    if _monitor_task is None or _monitor_task.done():
        logger.warning("[vless_monitor] Запуск монитора подписок VLESS (домашний интернет)")
        _monitor_task = asyncio.create_task(_monitor_loop(bot))


register_hook("periodic_notifications", _on_periodic)


# ── Кнопка ручной проверки в админ-панели ────────────────────────────────────

@register_hook("admin_panel")
def admin_panel_button(admin_role: str = "admin", **kwargs):
    btn = InlineKeyboardButton(
        text="🔍 Проверить подписки",
        callback_data=AdminPanelCallback(action="vless_monitor_check").pack(),
    )
    return {"button": btn}


@router.callback_query(AdminPanelCallback.filter(F.action == "vless_monitor_check"), IsAdminFilter())
async def handle_check_now(callback: CallbackQuery):
    from .settings import HOME_SSH_HOST, HOME_SSH_PORT, HOME_SSH_USER, HOME_SSH_PASS, CONNECT_TIMEOUT
    from database import async_session_maker, get_servers

    await callback.answer()
    await callback.message.edit_text("🔍 Скачиваю подписки с домашнего интернета...")

    try:
        async with async_session_maker() as session:
            servers_dict = await get_servers(session, include_enabled=True)
        targets = await _collect_targets(servers_dict)
    except Exception as e:
        await callback.message.edit_text(f"❌ Ошибка: {e}")
        return

    if not targets:
        await callback.message.edit_text("❌ Нет серверов для проверки.")
        return

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

    lines = []
    for name in sorted(results.keys()):
        ok = results[name]
        icon = "✅" if ok else "❌"
        sub_url = targets.get(name, "")
        # Показываем только хост подписки, без subId
        parsed = urlparse(sub_url)
        host_short = f"{parsed.hostname}:{parsed.port}"
        lines.append(f"{icon} <b>{name}</b> — <code>{host_short}</code>")

    up = sum(1 for ok in results.values() if ok)
    down = len(results) - up
    text = (
        f"🔍 Проверка подписок VLESS\n(домашний интернет → vless:// в ответе)\n\n"
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
