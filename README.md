# Unblock
Приложение, которое работает как dns proxy и прописывает статические маршруты роутеру keenetic для ip адресов, оказавшихся в [дампе роскомнадзора](https://github.com/zapret-info/z-i).

Переменные окружения для запуска:
- UNBLOCK_BIND_ADDR - ip-port для dns сервера (0.0.0.0:53) 
- UNBLOCK_DNS_UPSTREAM - ip-port dns upstream сервера (8.8.8.8:53)
- UNBLOCK_BLACKLIST_DUMP - ссылка на дамп  (https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv)
- UNBLOCK_ROUTER_API - ссылка на апи роутера без аутентификации (192.168.1.1:79)
- UNBLOCK_ROUTE_INTERFACE - название интерфейса, через который будет маршрутизироваться заблокированный ip адрес (OpenVPN1)
- UNBLOCK_BLACKLIST_UPDATE_INTERVAL_SEC - период обновления дампа в секундах (3600)
- UNBLOCK_DNS_REQUEST_TIMEOUT_MS - таймаут на запрос к dns upstream в миллисекундах (500)