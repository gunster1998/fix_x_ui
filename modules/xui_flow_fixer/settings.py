# Интервал между проверками (в часах). 0 = каждый запуск periodic_notifications
CHECK_INTERVAL_HOURS = 1

# Маппинг security → правильный flow
# none    = XHTTP (plain HTTP) — flow ОБЯЗАТЕЛЬНО пустой, иначе xray исключает клиента
# reality = Reality — ТРЕБУЕТ xtls-rprx-vision
# tls     = TLS — без Vision по умолчанию
SECURITY_FLOW_MAP = {
    "none":    "",
    "reality": "xtls-rprx-vision",
    "tls":     "",
}

# Что ставить если security неизвестен
DEFAULT_FLOW = "xtls-rprx-vision"
