"""
xui_flow_fixer — автоматически исправляет flow клиентов на 3x-ui серверах.

Проблема: бот добавляет всех клиентов с flow="xtls-rprx-vision", но для
XHTTP-inbound (security=none) xray полностью исключает таких клиентов из
running config — они не работают.

Решение: хук periodic_notifications проверяет каждый 3x-ui сервер,
определяет тип inbound и выставляет правильный flow через сырой httpx,
минуя pydantic (который падает на null limitIp и т.п.).
"""

import json
import httpx

from aiogram import Router
from datetime import datetime, timedelta

from hooks.hooks import register_hook
from logger import logger

router = Router(name="xui_flow_fixer")

_last_check: datetime | None = None


async def _periodic_fix(session, **kwargs):
    from .settings import CHECK_INTERVAL_HOURS, SECURITY_FLOW_MAP, DEFAULT_FLOW

    global _last_check
    now = datetime.utcnow()

    if CHECK_INTERVAL_HOURS > 0 and _last_check and (now - _last_check) < timedelta(hours=CHECK_INTERVAL_HOURS):
        return

    _last_check = now

    try:
        from database import get_servers
        from panels._3xui import get_xui_instance

        servers_dict = await get_servers(session, include_enabled=True)
        total_fixed = 0

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

                    fixed = await _fix_server_raw(
                        host=host,
                        session_cookie=session_cookie,
                        inbound_id=int(inbound_id),
                        server_name=server_name,
                        flow_map=SECURITY_FLOW_MAP,
                        default_flow=DEFAULT_FLOW,
                    )
                    total_fixed += fixed
                except Exception as e:
                    logger.error(f"[flow_fixer] Ошибка на сервере {server_name}: {e}")

        if total_fixed > 0:
            logger.warning(f"[flow_fixer] Исправлено {total_fixed} клиентов")
        else:
            logger.warning("[flow_fixer] Проверка завершена, исправлений не нужно")

    except Exception as e:
        logger.error(f"[flow_fixer] Критическая ошибка: {e}")


async def _fix_server_raw(
    host: str,
    session_cookie: str,
    inbound_id: int,
    server_name: str,
    flow_map: dict,
    default_flow: str,
) -> int:
    cookies = {"3x-ui": session_cookie}
    base = host.rstrip("/")

    async with httpx.AsyncClient(cookies=cookies, verify=False, timeout=15) as client:
        resp = await client.get(f"{base}/panel/api/inbounds/get/{inbound_id}")
        data = resp.json()

        if not data.get("success"):
            logger.warning(f"[flow_fixer] {server_name}: API ошибка: {data.get('msg')}")
            return 0

        inbound = data.get("obj", {})

        stream = inbound.get("streamSettings", {})
        if isinstance(stream, str):
            stream = json.loads(stream)

        security = stream.get("security", "").lower()
        network = stream.get("network", "").lower()
        correct_flow = flow_map.get(security, default_flow)

        settings = inbound.get("settings", {})
        if isinstance(settings, str):
            settings = json.loads(settings)

        clients = settings.get("clients", [])
        wrong = [c for c in clients if (c.get("flow") or "") != correct_flow]

        if not wrong:
            return 0

        logger.warning(
            f"[flow_fixer] {server_name}: {network}/{security} "
            f"→ flow={correct_flow!r}, "
            f"исправляю {len(wrong)}/{len(clients)} клиентов"
        )

        for c in clients:
            c["flow"] = correct_flow

        settings["clients"] = clients
        inbound["settings"] = json.dumps(settings)

        resp = await client.post(
            f"{base}/panel/api/inbounds/update/{inbound_id}",
            json=inbound,
        )
        result = resp.json()

        if result.get("success"):
            logger.warning(f"[flow_fixer] {server_name}: ✓ {len(wrong)} клиентов исправлено")
            return len(wrong)
        else:
            logger.error(f"[flow_fixer] {server_name}: update failed: {result.get('msg')}")
            return 0


register_hook("periodic_notifications", _periodic_fix)
