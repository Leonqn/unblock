# Unblock

DNS-прокси с выборочной маршрутизацией трафика и блокировкой рекламы для роутеров Keenetic.

## Установка на роутер Keenetic (Entware)

### Требования

- Роутер Keenetic с установленным [Entware](https://help.keenetic.com/hc/ru/articles/360021214160)
- Docker для кросс-компиляции

### 1. Сборка

Определите архитектуру вашего роутера и выберите соответствующий Docker-образ:

| Архитектура | Docker-образ | Таргет |
|---|---|---|
| MIPS (little-endian) | `messense/rust-musl-cross:mipsel-musl` | `mipsel-unknown-linux-musl` |
| MIPS (big-endian) | `messense/rust-musl-cross:mips-musl` | `mips-unknown-linux-musl` |
| ARM (aarch64) | `messense/rust-musl-cross:aarch64-musl` | `aarch64-unknown-linux-musl` |
| ARM (armv7) | `messense/rust-musl-cross:armv7-musl` | `armv7-unknown-linux-musleabihf` |

Пример для MIPS little-endian (Keenetic Extra II):

```bash
docker run --rm -v $(pwd):/app -w /app \
  messense/rust-musl-cross:mipsel-musl \
  cargo build --release --target mipsel-unknown-linux-musl
```

Бинарник: `target/<таргет>/release/unblock`.

### 2. Установка на роутер

Доставить бинарник и конфиг на роутер любым удобным способом (scp, curl, флешка и т.д.):

```
/opt/bin/unblock            — бинарник (chmod +x)
/opt/etc/unblock/config.yml — конфиг (на основе config.example.yml)
```

Создать директории:

```bash
mkdir -p /opt/etc/unblock /opt/var/unblock /opt/var/log
```

### 3. Настройка конфига

В `/opt/etc/unblock/config.yml` указать:

- `bind_addr: 0.0.0.0:53`
- `data_dir: /opt/var/unblock`
- Настроить секцию `unblock` (router_api_uri, route_interface) под свой роутер

### 4. Отключение встроенного DNS

Через CLI Keenetic (telnet на адрес роутера) отключить встроенный DNS-прокси, чтобы освободить порт 53:

```
opkg dns-override
system configuration save
```

Клиенты в сети продолжат получать адрес роутера как DNS-сервер по DHCP, но запросы будет обрабатывать unblock.

Откатить обратно:

```
no opkg dns-override
system configuration save
```

### 5. Init-скрипт

Создать `/opt/etc/init.d/S99unblock`:

```bash
#!/bin/sh

ENABLED=yes
PROCS=unblock
DESC=$PROCS

start() {
    echo "Starting $DESC..."
    RUST_LOG=info /opt/bin/$PROCS /opt/etc/unblock/config.yml \
        >> /opt/var/log/unblock.log 2>&1 &
}

stop() {
    echo "Stopping $DESC..."
    killall $PROCS 2>/dev/null
}

case "$1" in
    start) start ;;
    stop) stop ;;
    restart) stop; sleep 1; start ;;
    *) echo "Usage: $0 {start|stop|restart}" ;;
esac
```

```bash
chmod +x /opt/etc/init.d/S99unblock
```

### 6. Зависимости

```bash
opkg install ca-certificates ca-bundle logrotate
```

### 7. Ротация логов

Создать `/opt/etc/logrotate.d/unblock`:

```
/opt/var/log/unblock.log {
    size 1M
    rotate 2
    compress
    missingok
    copytruncate
}
```

Добавить в crontab (`crontab -e`):

```
0 * * * * /opt/sbin/logrotate /opt/etc/logrotate.conf
```

### 8. Запуск

```bash
/opt/etc/init.d/S99unblock start
tail -f /opt/var/log/unblock.log
```

Сервис автоматически запускается при загрузке роутера.

## Деплой

Для быстрого обновления бинарника на роутере есть скрипт `deploy.sh`. Он собирает проект, поднимает HTTP-сервер и по SSH обновляет бинарник на роутере.

### Требования

- Docker
- `sshpass` (`brew install esolitos/ipa/sshpass`)
- Python 3 (для HTTP-сервера)

### Использование

```bash
./deploy.sh
```

Скрипт выполняет:

1. Сборку для `mipsel-unknown-linux-musl` через Docker
2. Запуск HTTP-сервера в директории с бинарником
3. SSH на роутер (порт 222) → остановка сервиса → скачивание нового бинарника → запуск сервиса

При необходимости отредактируйте переменные в начале скрипта (`ROUTER_HOST`, `ROUTER_PORT`, `HTTP_PORT` и т.д.).

## Веб-интерфейс

После запуска доступен по адресу `http://<IP роутера>:<порт>/` (параметр `web_bind_addr` в конфиге).

Возможности:

- **Routed** — список IP-адресов, для которых прописаны маршруты
- **DNS Lookup** — ручная проверка резолва доменов
- **Stats** — статистика DNS-запросов: топ доменов, последние запросы, разбивка по устройствам

## Как это работает

### DNS-прокси

Все DNS-запросы от клиентов проходят через цепочку обработчиков:

```
Запрос клиента → Блокировка рекламы → Кеш → Unblock → Retry → Маршрутизация DNS → Upstream
```

По умолчанию запросы отправляются на UDP upstream (например, `8.8.8.8`), но можно настроить DoH (DNS-over-HTTPS) для большей приватности.

### dns_routing

Позволяет направлять запросы к определённым доменам на отдельные DNS-серверы. Например, домены `*.ru` можно резолвить через Яндекс DNS, а всё остальное — через Google/Cloudflare.

```yaml
dns_routing:
  - domains: ["*.ru", "*.xn--p1ai"]
    doh_upstreams:
      - https://common.dot.dns.yandex.net/dns-query
```

### unblock

Выборочная маршрутизация трафика через альтернативный интерфейс на основе списков доменов:

1. Загружает списки доменов из настроенных источников и периодически обновляет их
2. При DNS-запросе проверяет, есть ли домен в списке
3. Если домен найден — берёт IP-адреса из DNS-ответа и прописывает для них статические маршруты через API роутера Keenetic
4. Роутер направляет трафик к этим IP через указанный интерфейс (например, WireGuard)

DNS-ответ при этом не изменяется — клиент получает настоящие IP-адреса, просто трафик к ним идёт через другой интерфейс.

Маршруты автоматически удаляются по истечении `route_ttl`.

### ads_block

Блокировка рекламы и трекеров на уровне DNS:

1. Загружает фильтр в формате AdGuard и периодически обновляет его
2. При DNS-запросе проверяет домен по правилам фильтра
3. Если домен заблокирован — возвращает клиенту ответ NXDOMAIN (домен не существует), и запрос не проходит
4. Правила с префиксом `@@` работают как исключения (whitelist)

Можно добавить свои правила через `manual_rules` в конфиге:

```yaml
ads_block:
  manual_rules:
    - "@@||youtube.com^"     # не блокировать youtube
    - "||tracker.example^"   # заблокировать дополнительно
```

### Кеширование

DNS-ответы кешируются с учётом TTL из ответа. Это ускоряет повторные запросы и снижает нагрузку на upstream-серверы. Максимальный размер кеша настраивается через `cache_max_size`.
