"""
Встроенные значения по умолчанию: серверы, домены Xbox, шаблон ответа абоненту.

Пользователь может всё это поменять в файлах рядом с программой —
здесь только то, с чего программа стартует в первый раз.
"""

import ipaddress

# Servers for the first start (later they are loaded from servers.txt).
DEFAULT_SERVERS = [
    ("8.8.8.8", "Google"),
    ("8.8.4.4", "Google"),
    ("1.1.1.1", "Cloudflare"),
    ("1.0.0.1", "Cloudflare"),
    ("77.88.8.8", "Яндекс"),
    ("77.88.8.2", "Яндекс(защита)"),
    ("77.88.8.3", "Яндекс(семейный)"),
    ("9.9.9.9", "Quad9"),
    ("149.112.112.112", "Quad9"),
    ("208.67.222.222", "OpenDNS"),
    ("208.67.220.220", "OpenDNS"),
    ("111.88.96.54", "xbox-dns.ru"),
    ("111.88.96.55", "xbox-dns.ru"),
    ("45.90.33.120", "Кастомный"),
]

# Raise this number when DEFAULT_CONSOLES changes:
# then the old consoles.json is replaced with the new list.
CONSOLES_VERSION = 8

# Xbox domains we check through each DNS server.
#   host     — domain name
#   short    — short column title
#   what     — what this domain is for (tooltip)
#   critical — without it the user can't sign in
#   geo      — regional rules may apply; an anonymous probe cannot prove them
#   check    — "https" or "http" probe
#   method   — HTTP method (default GET)
#   path     — URL path (default "/")
#   headers  — extra HTTP headers
#   payload  — JSON body; deliberately invalid tokens never authenticate
#   expected — HTTP codes that prove a well-formed service response


DEFAULT_CONSOLES = {
    "_version": CONSOLES_VERSION,
    "Xbox": [
        {"host": "xsts.auth.xboxlive.com", "short": "Вход XBL",
         "what": "Вход: токен Xbox Live (региональные правила здесь не подтверждаются)",
         "critical": True, "geo": True, "check": "https", "method": "POST", "path": "/xsts/authorize",
         "headers": {"x-xbl-contract-version": "1"},
         "payload": {"Properties": {"SandboxId": "RETAIL", "UserTokens": ["intentionally-invalid-token"]},
                     "RelyingParty": "http://auth.xboxlive.com", "TokenType": "JWT"},
         "expected": [400, 401]},
        {"host": "user.auth.xboxlive.com", "short": "Вход польз.", "what": "Вход: авторизация пользователя",
         "critical": True, "check": "https", "method": "POST", "path": "/user/authenticate",
         "headers": {"x-xbl-contract-version": "1"},
         "payload": {"RelyingParty": "http://auth.xboxlive.com", "TokenType": "JWT",
                     "Properties": {"AuthMethod": "RPS", "SiteName": "user.auth.xboxlive.com",
                                    "RpsTicket": "d=intentionally-invalid-token"}},
         "expected": [400, 401]},
        {"host": "device.auth.xboxlive.com", "short": "Консоль", "what": "Авторизация консоли",
         "critical": True, "check": "https", "method": "POST", "path": "/device/authenticate"},
        {"host": "title.auth.xboxlive.com", "short": "Игры", "what": "Авторизация игр",
         "critical": True, "check": "https", "method": "POST", "path": "/title/authenticate"},
        {"host": "login.live.com", "short": "Аккаунт", "what": "Учётная запись Microsoft",
         "critical": True, "check": "https", "expected": [200, 301, 302]},
        {"host": "title.mgt.xboxlive.com", "short": "Сведения", "what": "Сведения об играх",
         "critical": True, "check": "https", "expected": [400, 401, 404]},
        {"host": "notify.xboxlive.com", "short": "Уведомления", "what": "Уведомления",
         "critical": False, "check": "https", "expected": [400, 401, 404]},
        {"host": "assets1.xboxlive.com", "short": "Загрузки", "what": "Загрузки игр и обновлений",
         "critical": False, "check": "http", "expected": [200, 400, 401, 404]},
        {"host": "clientconfig.passport.net", "short": "Passport", "what": "Вход и создание учётных записей",
         "critical": False, "check": "https", "expected": [200, 301, 302, 307, 308, 400, 401, 404]},
        {"host": "www.xbox.com", "short": "Сайт", "what": "Сайт / магазин",
         "critical": False, "check": "https", "expected": [200, 301, 302, 307, 308]},
        {"host": "www.msftconnecttest.com", "short": "Интернет (нов.)", "what": "Проверка «есть ли интернет» (новая)",
         "critical": False, "check": "http", "path": "/connecttest.txt"},
        {"host": "www.msftncsi.com", "short": "Интернет (стар.)", "what": "Проверка «есть ли интернет» (старая)",
         "critical": False, "check": "http", "path": "/ncsi.txt"},
    ],
}

# Well-known public DNS: IP -> provider tag.
KNOWN_PUBLIC_DNS = {
    "8.8.8.8": "google", "8.8.4.4": "google",
    "1.1.1.1": "cloudflare", "1.0.0.1": "cloudflare",
    "9.9.9.9": "quad9", "149.112.112.112": "quad9",
    "77.88.8.8": "yandex", "77.88.8.1": "yandex", "77.88.8.2": "yandex", "77.88.8.3": "yandex",
    "208.67.222.222": "opendns", "208.67.220.220": "opendns",
}

# Who may answer for each public DNS. The resolvers of a service often sit in the
# networks of its partners, so one name is not enough. Example: Quad9 servers are run
# by Packet Clearing House, and its network is registered as "WoodyNet, Inc."
# (seen on 9.9.9.9 and 149.112.112.112 — before this, it was shown as interception).
DNS_OWNER_NAMES = {
    "google": ("google",),
    "cloudflare": ("cloudflare",),
    "quad9": ("quad9", "woodynet", "packet clearing house"),
    "yandex": ("yandex",),
    "opendns": ("opendns", "cisco"),
}

# Microsoft / Azure networks: an answer inside them is a "real" Microsoft IP.
MICROSOFT_NETS = [ipaddress.ip_network(n) for n in (
    "20.0.0.0/8", "13.64.0.0/11", "40.64.0.0/10", "52.96.0.0/12", "104.40.0.0/13", "191.232.0.0/13",
)]
MICROSOFT_CNAMES = ("akadns.net", "trafficmanager.net", "azurefd.net", "azureedge.net", "msedge.net")

# The unmodified 3.x template can be upgraded without touching custom user text.
LEGACY_REPLY_TEMPLATE = (
    "Чтобы восстановить вход в Xbox Live, пропишите на консоли другие DNS-серверы:\n\n"
    "1. Нажмите кнопку Xbox на геймпаде и откройте «Профиль и система» → «Настройки».\n"
    "2. Перейдите в раздел «Общие» → «Параметры сети» → «Дополнительные настройки».\n"
    "3. Выберите «Параметры DNS» → «Вручную».\n"
    "4. Введите адреса:\n"
    "   Основной IPv4 DNS: {dns1}\n"
    "   Дополнительный IPv4 DNS: {dns2}\n"
    "5. Сохраните настройки и выберите «Проверить сетевое подключение».\n\n"
    "После этого перезагрузите консоль. Если ошибка сохранится, пришлите, пожалуйста, код ошибки с экрана — мы продолжим разбираться.\n"
)

# Text for the subscriber. {dns1} and {dns2} are replaced with addresses.
# The user can change it in reply_template.txt.
DEFAULT_REPLY_TEMPLATE = (
    "По проверке с нашего компьютера этот вариант DNS стоит попробовать. "
    "Гарантировать результат нельзя: окончательно он проверяется на вашей консоли.\n\n"
    "1. Нажмите кнопку Xbox на геймпаде и откройте «Профиль и система» → «Настройки».\n"
    "2. Перейдите в раздел «Общие» → «Параметры сети» → «Дополнительные настройки».\n"
    "3. Выберите «Параметры DNS» → «Вручную».\n"
    "4. Введите адреса:\n"
    "   Основной IPv4 DNS: {dns1}\n"
    "   Дополнительный IPv4 DNS: {dns2}\n"
    "5. Сохраните настройки, перезагрузите консоль и проверьте вход.\n\n"
    "Сторонний DNS получает DNS-запросы консоли, поэтому используйте только доверенные серверы. "
    "Если роутер позволяет, лучше перенаправлять через такой DNS только нужные домены Xbox, "
    "а не все запросы.\n\n"
    "Напишите, пожалуйста, помогло ли это. Если ошибка осталась или изменилась, "
    "пришлите её точный код с экрана — продолжим разбираться.\n"
)
