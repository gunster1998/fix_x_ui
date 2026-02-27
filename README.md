# xui_flow_fixer

Модуль для [Solo_bot](https://github.com/Nurullaev/NurVPN) / Chill_bot.

## Проблема

Бот добавляет клиентов на 3x-ui с `flow="xtls-rprx-vision"` для всех inbound-ов.
Для **XHTTP-inbound** (`security=none`) xray **полностью исключает** таких клиентов из running config — они не могут подключиться.

Симптом: клиенты есть в панели, но их нет в `config.json` → подключение не работает.

## Решение

Модуль подключается к хуку `periodic_notifications` и каждый час проверяет все 3x-ui серверы:

- Определяет тип протокола inbound по полю `security` в `streamSettings`
- Если flow у клиентов не соответствует правилу — исправляет одним вызовом `inbound.update`

| security | Правильный flow |
|----------|----------------|
| `none` (XHTTP) | `""` (пустой) |
| `reality` | `xtls-rprx-vision` |
| `tls` | `""` (пустой) |

## Установка

Скопировать папку `xui_flow_fixer` в `modules/` бота:

```
modules/
  xui_flow_fixer/
    __init__.py
    router.py
    settings.py
```

Перезапустить бота — модуль подхватится автоматически.

## Настройка

`settings.py`:

```python
# Интервал проверки в часах (0 = каждый цикл notifications, т.е. каждые 15 мин)
CHECK_INTERVAL_HOURS = 1

# security → flow
SECURITY_FLOW_MAP = {
    "none":    "",
    "reality": "xtls-rprx-vision",
    "tls":     "",
}
```

## Включение / отключение

Через админку бота: **Управление модулями → xui_flow_fixer**.

## Примечания

- Использует сырые httpx-запросы к x-ui API, минуя pydantic (который падает на `null` полях вроде `limitIp`)
- Логи на уровне `WARNING` — видны даже при `LOGGING_LEVEL = "WARNING"` в config.py
- Совместим с Solo_bot / Chill_bot на базе aiogram 3.x
