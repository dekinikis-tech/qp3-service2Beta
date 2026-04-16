import requests, os, re, subprocess, json, time, concurrent.futures
import urllib.parse, queue, socket, statistics, base64, urllib.request as url_req

# ============================================================
# НАСТРОЙКИ
# ============================================================
GID         = os.environ.get('MY_GIST_ID')
FILE_NAME   = "vps.txt"
SUB_FILE    = "sub.txt"
VIEWER_FILE = "index.html"
XRAY_BIN    = "xray"
TOP_N_EACH  = 300

# Этап 1 — быстрый TCP-пинг
TCP_WORKERS = 200          # увеличено: быстрее проверяем 10к серверов
TCP_TIMEOUT = 2.0          # чуть больше — меньше ложных отказов

# Этап 2 — глубокая проверка через xray
_slow = os.environ.get('MY_SLOW_NET') == '1'
XRAY_WORKERS       = 40    # увеличено с 20: быстрее xray-проверка
MAX_XRAY_TOTAL     = 10000 # снята искусственная планка — проверяем всех выживших
PING_ROUNDS        = 3
MAX_PING_MS        = 6000 if _slow else 5000  # чуть мягче — меньше ложных отказов
MAX_LOSS_RATE      = 0.67 if _slow else 0.67  # тоже мягче
REQUEST_TIMEOUT    = 15.0 if _slow else 10.0
XRAY_START_TIMEOUT = 6.0  if _slow else 4.5

# ============================================================
# ПРИОРИТЕТ REALITY
# Reality-серверы самые стабильные — они идут первыми на xray-проверку
# ============================================================
REALITY_BONUS_SCORE = -500  # вычитаем из score чтобы поднять выше в топе

TEST_URLS = [
    "http://www.gstatic.com/generate_204",
    "http://cp.cloudflare.com/",
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://www.msftncsi.com/ncsi.txt",
]

# ============================================================
# ИСТОЧНИКИ
# ============================================================
RU_SOURCES = [
    # Добавь RU-источники здесь если появятся
]

INT_SOURCES = [
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Splitted-By-Protocol/ss.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/ss.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt",
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/splitted-by-protocol/vless.txt",
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/splitted-by-protocol/trojan.txt",
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/splitted-by-protocol/shadowsocks.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/tr.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/ss.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/all_extracted_configs.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub3.txt",
]

SOURCES = RU_SOURCES + INT_SOURCES

# ============================================================
# ФИЛЬТРЫ — ИСПРАВЛЕНО
# Убран 'oneclick' — он уничтожал большинство серверов.
# Оставлены только реально вредные: российские сервисы и мусорные
# источники которые дают нерабочие конфиги.
# ============================================================
BLACK_LIST = [
    'meshky', '4mohsen', '708087',
    '4jadi', '4kian',
    'yandex.net', 'vk-apps.com', 'vk.com', 'mail.ru',
]

# BLOCKED_IPS: только Cloudflare WARP и Яндекс облако.
# Убраны широкие Cloudflare CDN диапазоны — они могут быть рабочими прокси.
BLOCKED_IPS = (
    '158.160.',   # Яндекс облако
    '51.250.',    # Яндекс облако
    '84.201.',    # Яндекс облако
    '130.193.',   # Яндекс облако
)

RU_IP_PREFIXES = (
    '46.8.', '46.17.', '46.29.', '46.36.', '46.39.', '46.40.', '46.41.',
    '46.101.', '46.102.', '46.148.', '77.37.', '77.91.', '79.133.', '79.174.',
    '80.64.', '80.87.', '80.240.', '80.250.', '82.146.', '82.148.', '83.166.',
    '83.220.', '83.222.', '85.10.', '85.119.', '85.142.', '85.143.', '85.209.',
    '86.62.', '87.117.', '87.249.', '88.218.', '89.108.', '89.110.', '89.111.',
    '89.249.', '90.150.', '90.156.', '91.90.', '91.108.', '91.185.', '91.193.',
    '91.194.', '91.213.', '91.215.', '91.217.', '91.219.', '91.220.', '91.221.',
    '91.222.', '91.223.', '92.63.', '92.119.', '92.222.', '93.95.', '93.153.',
    '93.157.', '93.158.', '94.26.', '94.130.', '94.140.', '94.142.', '94.143.',
    '94.154.', '94.247.', '95.46.', '95.47.', '95.165.', '95.213.', '95.215.',
    '95.216.', '95.217.', '95.241.', '95.247.', '101.42.', '103.21.', '109.71.',
    '109.172.', '109.195.', '109.234.', '178.18.', '178.21.', '178.124.', '178.137.',
    '178.154.', '178.155.', '185.4.', '185.6.', '185.7.', '185.12.', '185.16.',
    '185.22.', '185.36.', '185.55.', '185.67.', '185.68.', '185.71.', '185.80.',
    '185.83.', '185.87.', '185.100.', '185.103.', '185.105.', '185.112.', '185.123.',
    '185.126.', '185.130.', '185.133.', '185.146.', '185.151.', '185.161.', '185.163.',
    '185.164.', '185.170.', '185.173.', '185.177.', '185.178.', '185.180.', '185.184.',
    '185.185.', '185.188.', '185.189.', '185.190.', '185.191.', '185.192.', '185.195.',
    '185.196.', '185.197.', '185.198.', '185.199.', '185.200.', '185.201.', '185.204.',
    '185.209.', '185.210.', '185.211.', '185.212.', '185.215.', '185.216.', '185.220.',
    '185.225.', '185.226.', '185.229.', '185.230.', '185.231.', '185.234.', '185.238.',
    '185.246.', '185.247.', '195.2.', '195.3.', '195.10.', '195.12.', '195.14.',
    '195.16.', '195.19.', '195.22.', '195.24.', '195.25.', '195.34.', '195.42.',
    '195.43.', '195.47.', '195.49.', '195.58.', '195.62.', '195.64.', '195.65.',
    '195.80.', '195.82.', '195.88.', '195.90.', '195.91.', '195.93.', '195.94.',
    '195.96.', '195.128.', '195.133.', '195.144.', '195.149.', '195.151.', '195.154.',
    '195.160.', '195.161.', '195.162.', '195.163.', '195.165.', '195.166.', '195.168.',
    '195.170.', '195.174.', '195.175.', '195.182.', '195.184.', '195.185.', '195.189.',
    '195.190.', '195.191.', '195.194.', '195.196.', '195.197.', '195.198.', '195.199.',
    '195.200.', '195.201.', '195.203.', '195.204.', '195.206.', '195.208.', '195.209.',
    '195.210.', '195.211.', '195.214.', '195.215.', '195.218.', '195.219.', '195.220.',
    '195.222.', '195.225.', '195.226.', '195.227.', '195.230.', '195.232.', '195.233.',
    '195.234.', '195.238.', '195.239.', '195.240.', '195.242.', '195.244.', '195.245.',
    '195.246.', '195.248.', '195.249.', '195.250.', '195.251.', '195.253.', '195.254.',
    '212.33.', '212.47.', '212.109.', '213.24.', '213.33.', '213.87.', '213.145.',
    '213.148.', '213.167.', '213.183.', '213.184.', '213.188.', '213.189.', '213.194.',
    '213.195.', '213.202.', '213.203.', '213.206.', '213.207.', '213.208.', '213.219.',
    '213.220.', '213.222.', '213.226.', '213.227.', '213.228.', '213.230.', '213.232.',
    '213.234.', '213.243.', '213.248.', '216.24.',
    '62.84.',
    '94.250.',
)

RU_DOMAIN_KEYWORDS = (
    '.ru', '.su', 'yandex', 'vk.com', 'vk-apps', 'mail.ru',
    'selectel', 'beget', 'reg.ru', 'timeweb', 'hetzner.ru',
    'serverius', 'aeza.net', 'aeza.ru',
)

VLESS_REGEX = re.compile(
    r"vless://(?P<uuid>[^@]+)@(?P<host>[^:?#]+):(?P<port>\d+)\??(?P<query>[^#]+)?#?(?P<n>.*)?"
)

PROTO_REGEX = re.compile(
    r'(?:vless|trojan|hysteria2|ss)://[^\s\'"<>]+'
)

port_queue: queue.Queue = queue.Queue()
for _p in range(25000, 25000 + XRAY_WORKERS):
    port_queue.put(_p)


# ============================================================
# ГЕОЛОКАЦИЯ
# ============================================================

def _is_russian_server(address: str) -> bool:
    addr_lower = address.lower()
    if any(kw in addr_lower for kw in RU_DOMAIN_KEYWORDS):
        return True
    if address and address[0].isdigit():
        if address.startswith(RU_IP_PREFIXES):
            return True
    return False


def _is_reality(url: str) -> bool:
    """Определяет, использует ли сервер протокол Reality."""
    return 'security=reality' in url


# ============================================================
# ЭТАП 1: БЫСТРАЯ TCP-ПРОВЕРКА
# ============================================================

def _is_ipv6_address(host: str) -> bool:
    return ':' in host or (host.startswith('[') and host.endswith(']'))


def _extract_host_port(url: str):
    for pattern in (
        r'(?:vless|trojan)://[^@]+@([^:/?#\[\]]+|\[[^\]]+\]):(\d+)',
        r'hysteria2://[^@]+@([^:/?#\[\]]+|\[[^\]]+\]):(\d+)',
        r'ss://[^@]+@([^:/?#\[\]]+|\[[^\]]+\]):(\d+)',
    ):
        m = re.match(pattern, url)
        if m:
            return m.group(1).strip('[]'), int(m.group(2))
    return None, None


def tcp_alive(url: str) -> str | None:
    address, port = _extract_host_port(url)
    if address is None:
        return None
    if len(address) > 253:
        return None
    if _is_ipv6_address(address):
        return None
    if address.startswith(BLOCKED_IPS):
        return None
    addr_lower = address.lower()
    if any(bad in addr_lower for bad in BLACK_LIST):
        return None
    try:
        with socket.create_connection((address, port), timeout=TCP_TIMEOUT):
            return url
    except (OSError, UnicodeError, ValueError):
        return None


# ============================================================
# ЭТАП 2: ГЛУБОКАЯ ПРОВЕРКА ЧЕРЕЗ XRAY
# ============================================================

def _wait_for_port(host: str, port: int, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _build_xray_config(data: dict, port: int) -> dict:
    address     = data['host']
    server_port = int(data['port'])
    query       = urllib.parse.parse_qs(data.get('query') or '')

    def q(k, d=""):
        return query.get(k, [d])[0]

    sni    = q('sni', q('host', address))
    net    = q('type', 'tcp')
    sec    = q('security', 'none')
    stream: dict = {"network": net, "security": sec}

    if net == "ws":
        stream["wsSettings"] = {
            "path": urllib.parse.unquote(q("path", "/")),
            "headers": {"Host": q('host', address)},
        }
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": q("serviceName", "")}
    elif net == "h2":
        stream["httpSettings"] = {
            "host": [q('host', address)],
            "path": urllib.parse.unquote(q("path", "/")),
        }
    elif net == "splithttp":
        stream["splithttpSettings"] = {
            "path": urllib.parse.unquote(q("path", "/")),
            "host": q('host', address),
        }
    elif net == "xhttp":
        stream["xhttpSettings"] = {
            "path": urllib.parse.unquote(q("path", "/")),
            "host": q('host', address),
        }

    if sec == "reality":
        stream["realitySettings"] = {
            "serverName":  sni,
            "fingerprint": q("fp", "chrome"),
            "publicKey":   q("pbk"),
            "shortId":     q("sid"),
            "spiderX":     q("spx", "/"),
        }
    elif sec == "tls":
        stream["tlsSettings"] = {
            "serverName":      sni,
            "fingerprint":     q("fp", "chrome"),
            "allowInsecure":   q("allowInsecure", "0") == "1",
            "alpn":            ["h2", "http/1.1"],
        }

    flow = q("flow", "")

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "http"}],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": address,
                        "port":    server_port,
                        "users":   [{"id": data['uuid'], "encryption": "none", "flow": flow}],
                    }]
                },
                "streamSettings": stream,
            },
            {"tag": "block", "protocol": "blackhole"}
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "outboundTag": "proxy", "network": "tcp,udp"}]
        }
    }


def _build_xray_config_trojan(url: str, port: int) -> dict | None:
    m = re.match(
        r'trojan://([^@]+)@([^:/?#\[\]]+|\[[^\]]+\]):(\d+)\??([^#]*)?#?(.*)?', url
    )
    if not m:
        return None

    password    = m.group(1)
    address     = m.group(2).strip('[]')
    server_port = int(m.group(3))
    query       = urllib.parse.parse_qs(m.group(4) or '')

    def q(k, d=""):
        return query.get(k, [d])[0]

    sni    = q('sni', address)
    net    = q('type', 'tcp')
    sec    = q('security', 'tls')
    stream: dict = {"network": net, "security": sec}

    if net == "ws":
        stream["wsSettings"] = {
            "path": urllib.parse.unquote(q("path", "/")),
            "headers": {"Host": q('host', address)},
        }
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": q("serviceName", "")}

    if sec == "reality":
        stream["realitySettings"] = {
            "serverName":  sni,
            "fingerprint": q("fp", "chrome"),
            "publicKey":   q("pbk"),
            "shortId":     q("sid"),
            "spiderX":     q("spx", "/"),
        }
    elif sec == "tls":
        stream["tlsSettings"] = {
            "serverName":    sni,
            "fingerprint":   q("fp", "chrome"),
            "allowInsecure": q("allowInsecure", "0") == "1",
            "alpn":          ["h2", "http/1.1"],
        }

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "http"}],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "trojan",
                "settings": {
                    "servers": [{"address": address, "port": server_port, "password": password}]
                },
                "streamSettings": stream,
            },
            {"tag": "block", "protocol": "blackhole"}
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "outboundTag": "proxy", "network": "tcp,udp"}]
        }
    }


def test_via_xray(url: str):
    """
    Реальная проверка через xray для VLESS и Trojan.
    Hysteria2 и SS пропускаются — xray их не поддерживает как outbound в данной схеме,
    поэтому они вообще не добавляются в финальный список (только реально проверенные).
    """
    port     = port_queue.get()
    cfg_file = f"cfg_{port}.json"
    proc     = None
    try:
        if url.startswith('vless://'):
            match = VLESS_REGEX.match(url)
            if not match:
                return None
            config = _build_xray_config(match.groupdict(), port)
        elif url.startswith('trojan://'):
            config = _build_xray_config_trojan(url, port)
            if config is None:
                return None
        else:
            # hysteria2 и ss — xray не тестирует их через HTTP-прокси
            # НЕ даём фиктивный результат — пропускаем, чтобы не засорять топ
            return None

        with open(cfg_file, "w") as f:
            json.dump(config, f)

        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", cfg_file],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        if not _wait_for_port("127.0.0.1", port, XRAY_START_TIMEOUT):
            return None

        proxies = {
            "http":  f"http://127.0.0.1:{port}",
            "https": f"http://127.0.0.1:{port}",
        }
        session           = requests.Session()
        session.trust_env = False
        session.proxies   = proxies

        pings  = []
        losses = 0

        for _ in range(PING_ROUNDS):
            success = False
            for test_url in TEST_URLS:
                try:
                    t0      = time.perf_counter()
                    r       = session.get(test_url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
                    elapsed = int((time.perf_counter() - t0) * 1000)
                    # Принимаем: 200, 204 (connectivity check), 301/302 (редирект — соединение есть)
                    if r.status_code in (200, 204, 301, 302):
                        pings.append(elapsed)
                        success = True
                        break
                except Exception:
                    continue
            if not success:
                losses += 1

        if not pings:
            return None
        if losses / PING_ROUNDS > MAX_LOSS_RATE:
            return None

        avg_ping = int(statistics.mean(pings))
        if avg_ping > MAX_PING_MS:
            return None

        jitter = int(statistics.stdev(pings)) if len(pings) > 1 else 0

        # Reality-бонус: опускаем score вниз чтобы они оказались выше в топе
        is_reality = _is_reality(url)
        score = avg_ping + jitter // 2
        if is_reality:
            score = max(0, score + REALITY_BONUS_SCORE)

        return (url, score, avg_ping, jitter, losses)

    except Exception:
        return None
    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=2.0)
            except Exception:
                try: proc.kill()
                except Exception: pass
        if os.path.exists(cfg_file):
            os.remove(cfg_file)
        port_queue.put(port)


# ============================================================
# СБОР КОНФИГОВ
# ============================================================

def _decode_subscription(text: str) -> str:
    stripped = text.strip()
    if re.search(r'(?:vless|trojan|hysteria2|ss)://', stripped):
        return stripped
    for variant in (stripped, stripped.replace('-', '+').replace('_', '/')):
        padded = variant + '=' * ((-len(variant)) % 4)
        try:
            decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
            if re.search(r'(?:vless|trojan|hysteria2|ss)://', decoded):
                return decoded
        except Exception:
            continue
    lines_decoded = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        if re.search(r'(?:vless|trojan|hysteria2|ss)://', line):
            lines_decoded.append(line)
            continue
        try:
            padded       = line + '=' * ((-len(line)) % 4)
            decoded_line = base64.b64decode(padded).decode('utf-8', errors='ignore')
            if re.search(r'(?:vless|trojan|hysteria2|ss)://', decoded_line):
                lines_decoded.append(decoded_line)
        except Exception:
            continue
    return '\n'.join(lines_decoded) if lines_decoded else stripped


def _fetch_with_retry(url: str, retries: int = 3, delay: float = 2.0) -> str | None:
    headers = {'User-Agent': 'Mozilla/5.0'}
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(url, timeout=15, headers=headers)
            r.raise_for_status()
            return r.text
        except Exception as e:
            if attempt < retries:
                print(f"  [RETRY {attempt}/{retries}] {url}: {e}")
                time.sleep(delay)
            else:
                print(f"  [WARN] Не удалось загрузить после {retries} попыток: {url}: {e}")
    return None


def fetch_configs() -> tuple[list[str], set[str]]:
    all_raw: list[str] = []
    ru_keys: set[str]  = set()

    for source_url in SOURCES:
        is_ru_source = source_url in RU_SOURCES
        raw_text = _fetch_with_retry(source_url)
        if raw_text is None:
            continue
        text  = _decode_subscription(raw_text)
        found = PROTO_REGEX.findall(text)
        fmt   = "plain" if text is raw_text else "base64"
        tag   = "[RU]" if is_ru_source else "[INT]"
        print(f"  {tag} {source_url.split('/')[-1]}  →  {len(found)} конфигов  [{fmt}]")
        all_raw.extend(found)

        if is_ru_source:
            for cfg in found:
                host, port = _extract_host_port(cfg)
                if host and port:
                    ru_keys.add(f"{host}:{port}")

    seen_endpoints: set[str] = set()
    unique: list[str] = []
    for cfg in all_raw:
        host, port = _extract_host_port(cfg)
        if host and port:
            key = f"{host}:{port}"
            if key not in seen_endpoints:
                seen_endpoints.add(key)
                unique.append(cfg)
        else:
            unique.append(cfg)

    return unique, ru_keys


# ============================================================
# ГЕНЕРАЦИЯ HTML
# ============================================================

def _get_proto(url: str) -> str:
    for p in ('vless', 'trojan', 'hysteria2', 'ss'):
        if url.startswith(p + '://'):
            return p.upper()
    return 'UNKNOWN'


def _get_security(url: str) -> str:
    m = re.search(r'[?&]security=([^&#+]+)', url)
    if m:
        return m.group(1)
    if 'trojan://' in url:
        return 'tls'
    return 'none'


def _get_network(url: str) -> str:
    m = re.search(r'[?&]type=([^&#+]+)', url)
    return m.group(1) if m else 'tcp'


def generate_html_viewer(intl_results: list, ru_results: list, elapsed: int) -> str:

    def ping_color(avg):
        if avg < 300:  return '#22c55e'
        if avg < 1000: return '#f59e0b'
        return '#ef4444'

    def make_rows(results):
        rows = []
        for i, (url, score, avg, jitter, losses) in enumerate(results, 1):
            proto    = _get_proto(url)
            security = _get_security(url)
            network  = _get_network(url)
            host, _  = _extract_host_port(url)
            tag      = urllib.parse.unquote(url.split('#')[-1])[:36] if '#' in url else (host or '')[:36]
            is_ru    = _is_russian_server(host or '')
            flag     = '\U0001f1f7\U0001f1fa' if is_ru else '\U0001f30d'
            loss_pct = int(losses / PING_ROUNDS * 100)
            pc       = ping_color(avg)
            safe_url = url.replace('&', '&amp;').replace('"', '&quot;').replace('<', '&lt;').replace("'", '&#39;')
            safe_tag = tag.replace('<', '&lt;').replace('>', '&gt;')

            # Reality-метка
            reality_mark = ' ⚡' if security == 'reality' else ''

            proto_colors = {
                'VLESS':     ('rgba(99,102,241,0.15)', '#a5b4fc', 'rgba(99,102,241,0.35)'),
                'TROJAN':    ('rgba(234,179,8,0.12)',  '#fde047', 'rgba(234,179,8,0.35)'),
                'SS':        ('rgba(34,197,94,0.12)',  '#86efac', 'rgba(34,197,94,0.3)'),
                'HYSTERIA2': ('rgba(236,72,153,0.12)', '#f9a8d4', 'rgba(236,72,153,0.3)'),
            }
            pbg, ptxt, pborder = proto_colors.get(proto, ('rgba(148,163,184,0.1)', '#94a3b8', 'rgba(148,163,184,0.25)'))

            sec_colors = {
                'reality': ('rgba(168,85,247,0.18)', '#c084fc', 'rgba(168,85,247,0.5)'),
                'tls':     ('rgba(34,197,94,0.1)',   '#86efac', 'rgba(34,197,94,0.25)'),
                'none':    ('rgba(148,163,184,0.08)','#64748b',  'rgba(148,163,184,0.2)'),
            }
            sbg, stxt, sborder = sec_colors.get(security, ('rgba(148,163,184,0.08)', '#64748b', 'rgba(148,163,184,0.2)'))

            rows.append(
                f'<tr class="srv-row" data-ping="{avg}" data-proto="{proto}" data-loss="{loss_pct}" data-sec="{security}">' +
                f'<td class="td-num">{i}</td>' +
                f'<td class="td-name"><span class="srv-flag">{flag}</span><span class="srv-tag" title="{safe_tag}">{safe_tag}{reality_mark}</span></td>' +
                f'<td class="td-badge"><span class="badge" style="background:{pbg};color:{ptxt};border-color:{pborder}">{proto}</span></td>' +
                f'<td class="td-badge td-hide"><span class="badge badge-sm" style="background:rgba(148,163,184,0.08);color:#94a3b8;border-color:rgba(148,163,184,0.2)">{network}</span></td>' +
                f'<td class="td-badge td-hide"><span class="badge badge-sm" style="background:{sbg};color:{stxt};border-color:{sborder}">{security}</span></td>' +
                f'<td class="td-ping"><span class="ping-val" style="color:{pc}">{avg}</span><span class="ping-unit">ms</span></td>' +
                f'<td class="td-jitter td-hide" style="color:#64748b;font-family:monospace;font-size:11px">{jitter}ms</td>' +
                f'<td class="td-loss"><span class="loss-dot" style="background:{"#22c55e" if loss_pct==0 else "#ef4444"}"></span><span style="color:{"#22c55e" if loss_pct==0 else "#ef4444"};font-size:12px">{loss_pct}%</span></td>' +
                f'<td class="td-copy"><button class="copy-btn" onclick="copyVpn(this)" data-url="{safe_url}" title="Copy config"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg></button></td>' +
                f'</tr>'
            )
        return '\n'.join(rows)

    intl_rows = make_rows(intl_results)
    ru_rows   = make_rows(ru_results)
    total     = len(intl_results) + len(ru_results)
    updated   = time.strftime('%d %b %Y · %H:%M UTC', time.gmtime())
    best_ping = min((r[2] for r in intl_results), default=0)
    reality_count = sum(1 for r in (intl_results + ru_results) if _is_reality(r[0]))

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Scout</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg0:#070b14;--bg1:#0d1117;--bg2:#111827;--bg3:#1a2233;
  --border:#1e2d3d;--border2:#253347;
  --text:#e2e8f0;--text2:#94a3b8;--text3:#475569;
  --accent:#3b82f6;--accent2:#60a5fa;
  --green:#22c55e;--yellow:#f59e0b;--red:#ef4444;
  --reality:#a855f7;
  --radius:8px;--radius-lg:12px;
}}
body{{background:var(--bg0);color:var(--text);font-family:'Inter',sans-serif;font-size:13px;min-height:100vh;line-height:1.5}}
.header{{background:var(--bg1);border-bottom:1px solid var(--border);padding:0 24px;display:flex;align-items:center;justify-content:space-between;height:56px;position:sticky;top:0;z-index:100}}
.logo{{display:flex;align-items:center;gap:10px;font-weight:600;font-size:15px}}
.logo-icon{{width:28px;height:28px;background:linear-gradient(135deg,#3b82f6,#8b5cf6);border-radius:7px;display:flex;align-items:center;justify-content:center}}
.header-meta{{font-size:11px;color:var(--text3);font-family:'JetBrains Mono',monospace}}
.stats-bar{{display:grid;grid-template-columns:repeat(5,1fr);gap:1px;background:var(--border);border-bottom:1px solid var(--border)}}
.stat{{background:var(--bg1);padding:16px 20px;text-align:center}}
.stat-val{{font-size:22px;font-weight:600;font-family:'JetBrains Mono',monospace;line-height:1}}
.stat-lbl{{font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-top:5px}}
.content{{padding:20px 20px 40px;max-width:1200px;margin:0 auto}}
.tabs{{display:flex;gap:6px;margin-bottom:16px;align-items:center}}
.tab-btn{{padding:7px 18px;border-radius:var(--radius);border:1px solid var(--border2);background:transparent;color:var(--text2);font-size:13px;font-weight:500;cursor:pointer;font-family:'Inter',sans-serif;transition:all .15s}}
.tab-btn:hover{{background:var(--bg3);color:var(--text)}}
.tab-btn.active{{background:var(--bg3);border-color:var(--accent);color:var(--accent2)}}
.tab-btn.active-ru{{border-color:#f97316;color:#fb923c;background:var(--bg3)}}
.filter-group{{margin-left:auto;display:flex;gap:6px}}
.filter-select{{background:var(--bg2);border:1px solid var(--border2);color:var(--text2);border-radius:var(--radius);padding:6px 10px;font-size:12px;font-family:'Inter',sans-serif;cursor:pointer;outline:none}}
.table-card{{background:var(--bg1);border:1px solid var(--border);border-radius:var(--radius-lg);overflow:hidden}}
.tbl-wrap{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse}}
thead th{{background:var(--bg0);color:var(--text3);font-size:10px;text-transform:uppercase;letter-spacing:.07em;padding:10px 14px;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap;font-weight:500}}
.srv-row{{border-bottom:1px solid var(--border);transition:background .1s}}
.srv-row:last-child{{border-bottom:none}}
.srv-row:hover{{background:var(--bg2)}}
.srv-row[data-sec="reality"]{{border-left:2px solid rgba(168,85,247,0.4)}}
.td-num{{padding:10px 14px;color:var(--text3);font-size:11px;width:36px;font-family:monospace}}
.td-name{{padding:10px 14px;max-width:200px}}
.srv-flag{{font-size:13px;margin-right:6px}}
.srv-tag{{font-size:12px;color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block;max-width:180px;vertical-align:bottom}}
.td-badge{{padding:10px 14px}}
.badge{{display:inline-flex;align-items:center;padding:2px 8px;border-radius:5px;font-size:10px;font-weight:600;letter-spacing:.04em;border:1px solid;font-family:monospace}}
.badge-sm{{font-weight:400}}
.td-ping{{padding:10px 14px;white-space:nowrap}}
.ping-val{{font-size:14px;font-weight:600;font-family:monospace}}
.ping-unit{{font-size:10px;color:var(--text3);margin-left:1px}}
.td-jitter{{padding:10px 14px}}
.td-loss{{padding:10px 14px;display:flex;align-items:center;gap:5px}}
.loss-dot{{width:6px;height:6px;border-radius:50%;flex-shrink:0}}
.td-copy{{padding:10px 14px}}
.copy-btn{{background:var(--bg3);border:1px solid var(--border2);color:var(--text2);border-radius:6px;padding:5px 8px;cursor:pointer;display:flex;align-items:center;transition:all .15s}}
.copy-btn:hover{{background:rgba(59,130,246,0.15);border-color:var(--accent);color:var(--accent2)}}
.copy-btn.ok{{background:rgba(34,197,94,0.15);border-color:#22c55e;color:#22c55e}}
.empty{{padding:40px;text-align:center;color:var(--text3)}}
.sub-banner{{background:rgba(59,130,246,0.07);border:1px solid rgba(59,130,246,0.18);border-radius:var(--radius);padding:11px 16px;margin-bottom:16px;font-size:12px;color:var(--text2);display:flex;align-items:center;gap:8px;flex-wrap:wrap}}
.sub-banner code{{font-family:'JetBrains Mono',monospace;color:var(--accent2);font-size:11px;background:rgba(59,130,246,0.1);padding:2px 6px;border-radius:4px}}
#toast{{position:fixed;bottom:20px;right:20px;background:#22c55e;color:#052e16;font-weight:600;font-size:12px;padding:9px 16px;border-radius:var(--radius);opacity:0;transform:translateY(6px);transition:all .2s;pointer-events:none;z-index:999}}
#toast.show{{opacity:1;transform:translateY(0)}}
@media(max-width:680px){{.td-hide{{display:none}}.stats-bar{{grid-template-columns:repeat(3,1fr)}}.content{{padding:12px}}.filter-group{{display:none}}}}
</style>
</head>
<body>
<header class="header">
  <div class="logo">
    <div class="logo-icon">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    </div>
    VPN Scout
  </div>
  <div class="header-meta">Updated {updated} &nbsp;·&nbsp; Scan: {elapsed}s</div>
</header>
<div class="stats-bar">
  <div class="stat"><div class="stat-val" style="color:var(--accent2)">{len(intl_results)}</div><div class="stat-lbl">International</div></div>
  <div class="stat"><div class="stat-val" style="color:#fb923c">{len(ru_results)}</div><div class="stat-lbl">Russian</div></div>
  <div class="stat"><div class="stat-val">{total}</div><div class="stat-lbl">Total alive</div></div>
  <div class="stat"><div class="stat-val" style="color:var(--green)">{best_ping}ms</div><div class="stat-lbl">Best ping</div></div>
  <div class="stat"><div class="stat-val" style="color:var(--reality)">⚡{reality_count}</div><div class="stat-lbl">Reality</div></div>
</div>
<div class="content">
<div class="sub-banner">
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#60a5fa" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4m0 4h.01"/></svg>
  Подписка: <code>https://gist.githubusercontent.com/YOUR_USER/YOUR_GIST_ID/raw/sub.txt</code>
  &nbsp;·&nbsp; ⚡ = Reality (приоритет). Нажми Copy для прямого копирования конфига.
</div>
<div class="tabs">
  <button class="tab-btn active" id="btn-intl" onclick="showTab('intl')">
    🌍 International <span style="background:rgba(59,130,246,0.15);color:var(--accent2);border-radius:20px;padding:1px 7px;font-size:11px;margin-left:4px">{len(intl_results)}</span>
  </button>
  <button class="tab-btn" id="btn-ru" onclick="showTab('ru')">
    🇷🇺 Russian <span style="background:rgba(249,115,22,0.12);color:#fb923c;border-radius:20px;padding:1px 7px;font-size:11px;margin-left:4px">{len(ru_results)}</span>
  </button>
  <div class="filter-group">
    <select class="filter-select" id="proto-filter" onchange="applyFilters()">
      <option value="">All protocols</option>
      <option value="VLESS">VLESS</option>
      <option value="TROJAN">TROJAN</option>
    </select>
    <select class="filter-select" id="sec-filter" onchange="applyFilters()">
      <option value="">All security</option>
      <option value="reality">⚡ Reality</option>
      <option value="tls">TLS</option>
      <option value="none">None</option>
    </select>
    <select class="filter-select" id="sort-select" onchange="applyFilters()">
      <option value="ping">Sort: Ping ↑</option>
      <option value="loss">Sort: Loss ↑</option>
    </select>
  </div>
</div>
<div class="table-card" id="sec-intl">
  <div class="tbl-wrap"><table>
    <thead><tr><th>#</th><th>Server</th><th>Protocol</th><th class="td-hide">Network</th><th class="td-hide">Security</th><th>Ping</th><th class="td-hide">Jitter</th><th>Loss</th><th></th></tr></thead>
    <tbody id="body-intl">{intl_rows if intl_rows else '<tr><td colspan="9"><div class="empty">No servers</div></td></tr>'}</tbody>
  </table></div>
</div>
<div class="table-card" id="sec-ru" style="display:none">
  <div class="tbl-wrap"><table>
    <thead><tr><th>#</th><th>Server</th><th>Protocol</th><th class="td-hide">Network</th><th class="td-hide">Security</th><th>Ping</th><th class="td-hide">Jitter</th><th>Loss</th><th></th></tr></thead>
    <tbody id="body-ru">{ru_rows if ru_rows else '<tr><td colspan="9"><div class="empty">No servers</div></td></tr>'}</tbody>
  </table></div>
</div>
</div>
<div id="toast">Copied!</div>
<script>
var activeTab='intl';
function showTab(name){{
  activeTab=name;
  document.getElementById('sec-intl').style.display=name==='intl'?'':'none';
  document.getElementById('sec-ru').style.display=name==='ru'?'':'none';
  document.getElementById('btn-intl').className='tab-btn'+(name==='intl'?' active':'');
  document.getElementById('btn-ru').className='tab-btn'+(name==='ru'?' active-ru':'');
  applyFilters();
}}
function applyFilters(){{
  var proto=document.getElementById('proto-filter').value;
  var sec=document.getElementById('sec-filter').value;
  var sort=document.getElementById('sort-select').value;
  var bodyId=activeTab==='intl'?'body-intl':'body-ru';
  var body=document.getElementById(bodyId);
  var rows=Array.from(body.querySelectorAll('.srv-row'));
  rows.forEach(function(r){{
    var protoOk=!proto||r.getAttribute('data-proto')===proto;
    var secOk=!sec||r.getAttribute('data-sec')===sec;
    r.style.display=(protoOk&&secOk)?'':'none';
  }});
  var vis=rows.filter(function(r){{return r.style.display!=='none';}});
  vis.sort(function(a,b){{
    var k=sort==='loss'?'data-loss':'data-ping';
    return parseInt(a.getAttribute(k))-parseInt(b.getAttribute(k));
  }});
  vis.forEach(function(r,i){{body.appendChild(r);r.querySelector('.td-num').textContent=i+1;}});
}}
function copyVpn(btn){{
  var url=btn.getAttribute('data-url');
  var ta=document.createElement('textarea');
  ta.value=url;ta.style.cssText='position:fixed;left:-9999px;opacity:0';
  document.body.appendChild(ta);ta.select();
  try{{
    document.execCommand('copy');
    btn.classList.add('ok');
    btn.innerHTML='<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>';
    var t=document.getElementById('toast');t.className='show';
    setTimeout(function(){{
      btn.classList.remove('ok');
      btn.innerHTML='<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>';
      t.className='';
    }},1600);
  }}catch(e){{alert('Copy failed');}}
  document.body.removeChild(ta);
}}
</script>
</body>
</html>"""


def run():
    t_start = time.time()
    print("=" * 60)
    print("  VPN SCOUT — оптимизированная версия")
    print(f"  TCP-воркеры   : {TCP_WORKERS}  (таймаут {TCP_TIMEOUT}с)")
    print(f"  Xray-воркеры  : {XRAY_WORKERS}  (таймаут {XRAY_START_TIMEOUT}с)")
    print(f"  Раундов       : {PING_ROUNDS},  макс. пинг: {MAX_PING_MS}мс")
    print(f"  Топ каждой гео: {TOP_N_EACH}")
    print(f"  Макс. xray-проверок: {MAX_XRAY_TOTAL}")
    print(f"  Динамический таймаут (MY_SLOW_NET): {'ВКЛ' if _slow else 'ВЫКЛ'}")
    print(f"  Reality-приоритет: ВКЛ (бонус {REALITY_BONUS_SCORE}мс к score)")
    print(f"  Base64-подписка: {SUB_FILE}")
    print(f"  Источников: {len(RU_SOURCES)} RU + {len(INT_SOURCES)} INT = {len(SOURCES)} всего")
    print("=" * 60)

    # --- [1/4] Сбор ---
    print("\n[1/4] Сбор конфигов...")
    all_configs, ru_source_keys = fetch_configs()
    print(f"      Итого уникальных (по хосту:порту): {len(all_configs)}")
    if not all_configs:
        print("Нет кандидатов.")
        return

    # --- [2/4] TCP ---
    print(f"\n[2/4] Быстрая TCP-проверка ({TCP_WORKERS} воркеров)...")
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=TCP_WORKERS) as ex:
        for future in concurrent.futures.as_completed(
            {ex.submit(tcp_alive, u): u for u in all_configs}
        ):
            result = future.result()
            if result:
                alive.append(result)

    elapsed_tcp = int(time.time() - t_start)
    print(f"      TCP живых: {len(alive)} / {len(all_configs)}  ({elapsed_tcp}с)")
    if not alive:
        print("Нет живых серверов после TCP-проверки.")
        return

    # Reality-серверы идут первыми на xray-проверку — они важнее
    alive_sorted = sorted(alive, key=lambda u: (0 if _is_reality(u) else 1))
    reality_in_alive = sum(1 for u in alive if _is_reality(u))
    print(f"      Из них Reality: {reality_in_alive}")

    # --- [3/4] Xray ---
    to_check = alive_sorted[:MAX_XRAY_TOTAL]
    print(f"\n[3/4] Глубокая xray-проверка ({len(to_check)} серверов, {XRAY_WORKERS} воркеров)...")
    print(f"      Reality идут первыми в очереди ({reality_in_alive} шт.)")
    results = []
    tested  = 0
    total   = len(to_check)

    with concurrent.futures.ThreadPoolExecutor(max_workers=XRAY_WORKERS) as ex:
        futures = {ex.submit(test_via_xray, u): u for u in to_check}
        for future in concurrent.futures.as_completed(futures):
            tested += 1
            if tested % 100 == 0 or tested == total:
                reality_ok = sum(1 for r in results if _is_reality(r[0]))
                print(f"  Прогресс: {tested}/{total}  |  Прошли xray: {len(results)}  |  Reality OK: {reality_ok}")
            res = future.result()
            if res:
                results.append(res)

    elapsed_total = int(time.time() - t_start)

    # --- [4/4] Сохранение ---
    print(f"\n[4/4] Сохранение...")
    if not results:
        print("❌ Нет рабочих серверов. Старый файл сохранён.")
        return

    results.sort(key=lambda x: x[1])  # сортировка по score (Reality идут выше)

    intl_all = []
    ru_all   = []
    for entry in results:
        host, port = _extract_host_port(entry[0])
        key = f"{host}:{port}" if host and port else ""
        if key in ru_source_keys:
            ru_all.append(entry)
        else:
            intl_all.append(entry)

    intl_results = intl_all[:TOP_N_EACH]
    ru_results   = ru_all[:TOP_N_EACH]

    reality_total = sum(1 for r in (intl_results + ru_results) if _is_reality(r[0]))

    print(f"\n{'─'*60}")
    print(f"  Всего: {len(all_configs)} → TCP: {len(alive)} → xray: {len(results)}")
    print(f"  🌍 Зарубежных: найдено {len(intl_all)}, в топе: {len(intl_results)}")
    print(f"  🇷🇺 Российских: найдено {len(ru_all)}, в топе: {len(ru_results)}")
    print(f"  ⚡ Reality в финале: {reality_total}")
    print(f"  Время: {elapsed_total}с")
    print(f"{'─'*60}")

    print("\n  Топ-10 зарубежных:")
    for i, (url, score, avg, jitter, losses) in enumerate(intl_results[:10], 1):
        name = urllib.parse.unquote(url.split('#')[-1])[:40] if '#' in url else url[8:48]
        sec  = _get_security(url)
        mark = " ⚡Reality" if sec == "reality" else f" [{sec}]"
        print(f"  {i:<3} {avg:>5}мс  jitter:{jitter:>4}мс  loss:{losses}/{PING_ROUNDS}{mark}  {name}")

    if ru_results:
        print("\n  Топ-10 российских:")
        for i, (url, score, avg, jitter, losses) in enumerate(ru_results[:10], 1):
            name = urllib.parse.unquote(url.split('#')[-1])[:40] if '#' in url else url[8:48]
            sec  = _get_security(url)
            mark = " ⚡Reality" if sec == "reality" else f" [{sec}]"
            print(f"  {i:<3} {avg:>5}мс  jitter:{jitter:>4}мс  loss:{losses}/{PING_ROUNDS}{mark}  {name}")

    final_urls = [r[0] for r in intl_results] + [r[0] for r in ru_results]

    with open(FILE_NAME, "w", encoding="utf-8") as f:
        f.write("\n".join(final_urls))
    print(f"\n✅ Сохранено {len(final_urls)} серверов в {FILE_NAME}")

    b64_content = base64.b64encode("\n".join(final_urls).encode("utf-8")).decode("utf-8")
    with open(SUB_FILE, "w", encoding="utf-8") as f:
        f.write(b64_content)
    print(f"✅ Base64-подписка сохранена в {SUB_FILE}")

    html = generate_html_viewer(intl_results, ru_results, elapsed_total)
    with open(VIEWER_FILE, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"✅ HTML-viewer сохранён в {VIEWER_FILE}")

    if GID:
        print("Обновляем Gist (три файла: vps.txt + sub.txt + index.html)...")

        token = os.environ.get('GH_TOKEN')
        if not token:
            try:
                token_res = subprocess.run(
                    ["gh", "auth", "token"], capture_output=True, text=True
                )
                token = token_res.stdout.strip()
            except Exception:
                token = None

        if token:
            payload = json.dumps({
                "files": {
                    FILE_NAME:   {"content": "\n".join(final_urls)},
                    SUB_FILE:    {"content": b64_content},
                    VIEWER_FILE: {"content": html},
                }
            }).encode("utf-8")

            req = url_req.Request(
                f"https://api.github.com/gists/{GID}",
                data=payload,
                method="PATCH",
                headers={
                    "Authorization":        f"Bearer {token}",
                    "Content-Type":         "application/json",
                    "Accept":               "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                }
            )
            try:
                with url_req.urlopen(req) as resp:
                    if resp.status == 200:
                        print("✅ Gist обновлён.")
                    else:
                        print(f"❌ Gist ошибка: статус {resp.status}")
            except Exception as e:
                print(f"❌ Gist ошибка: {e}")
        else:
            print("❌ Не удалось получить токен GitHub (GH_TOKEN)!")
    else:
        print("⚠️  MY_GIST_ID не задан — локальный запуск, файлы сохранены локально.")


if __name__ == "__main__":
    run()
