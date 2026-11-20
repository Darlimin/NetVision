"""Pure presentation decisions for the dashboard."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

GREEN, AMBER, RED, GREY = "#22c55e", "#f59e0b", "#ef4444", "#64748b"
GATEWAY_WARNING_MS = 15
JITTER_WARNING_MS = 15
METRIC_HELP = {
    "dns": "Скорость превращения адреса сайта в IP. Медленный DNS замедляет открытие страниц и вход в игровые лобби.",
    "ping": "Время отклика до сервера и обратно. Чем ниже цифра, тем быстрее регистрируются действия в игре.",
    "loss": "Процент пропавших пакетов. Значение выше 0% вызывает рывки, пропуски звука и вылеты.",
    "jitter": "Разброс задержки. Высокий джиттер вызывает телепортацию персонажей даже при низком пинге.",
    "tcp": "Проверка надёжного веб-соединения и шифрования. Для онлайн-игр по UDP не используются.",
    "tls": "Проверка надёжного веб-соединения и шифрования. Для онлайн-игр по UDP не используются.",
}
LATENCY_HELP = (
    "История пинга за последнюю минуту. Ровная линия — стабильная связь, резкие пики вверх — лаги."
)
VPN_MAIN_HINT = "Активен VPN (TUN): локальный перехват может занижать PING и TCP. Реальную задержку смотрите по TLS handshake."
VPN_DNS_HINT = "Активен VPN (TUN): запросы TCP/53 могут перехватываться локально. Для сравнения проверьте соединение без VPN."
VPN_MTR_HINT = "Активен VPN (TUN): промежуточные узлы провайдера могут быть скрыты туннелем."
GAME_AUTO_HELP = "Ищет запущенную игру и её игровой UDP-сокет, затем запускает диагностику."
GAME_PRESET_HELP = "Ручная проверка адреса игрового сервера, в том числе до запуска игры."
MTR_HELP = "Путь трафика через промежуточные узлы провайдера. Помогает найти точное место потерь."
BUFFERBLOAT_HELP = (
    "Рост пинга под нагрузкой (скачивание файлов, торренты, 4K-видео в домашней сети)."
)
MTU_HELP = "Максимальный размер одного пакета. Неправильный MTU мешает открытию сайтов и работе голосовых чатов через VPN."
NAT_HELP = "Тип сетевой трансляции. Открытый/умеренный NAT нужен для стабильного голоса и P2P-игр."
GAME_PROCESSES = frozenset(
    name.casefold()
    for name in (
        "HuntGame.exe",
        "cs2.exe",
        "dota2.exe",
        "VALORANT-Win64-Shipping.exe",
        "r5apex.exe",
        "TslGame.exe",
        "EscapeFromTarkov.exe",
        "FortniteClient-Win64-Shipping.exe",
        "aces.exe",
        "Overwatch.exe",
        "Destiny2.exe",
        "RustClient.exe",
        "Deadlock.exe",
        "cod.exe",
        "bf2042.exe",
    )
)


@dataclass(frozen=True, slots=True)
class MetricAssessment:
    color: str
    text: str
    state: str


def metric_assessment(
    key: str,
    value: float | None,
    *,
    error: bool = False,
    vpn: bool = False,
    udp: bool = False,
    bare_ip: bool = False,
    expires_days: float | None = None,
) -> MetricAssessment:
    if udp and key in {"tcp", "tls"}:
        return MetricAssessment(GREY, "Не для UDP", "neutral")
    if key == "tls" and bare_ip:
        return MetricAssessment(GREY, "Требует домен", "neutral")
    if error:
        text = {"dns": "Медленно", "ping": "Высокий", "tcp": "Задержка", "tls": "Ошибка"}.get(
            key, "Нет данных"
        )
        return MetricAssessment(RED, text, "error")
    if key == "tls":
        if value is None:
            return MetricAssessment(GREY, "Нет данных", "neutral")
        if expires_days is not None and expires_days < 14:
            return MetricAssessment(AMBER, "Внимание", "warning")
        return MetricAssessment(GREEN, "Защищено", "good")
    if value is None:
        return MetricAssessment(GREY, "Нет данных", "neutral")
    if key == "dns" and vpn and value < 1:
        return MetricAssessment(GREY, "Локальный кэш/VPN", "neutral")
    if key == "loss":
        if value == 0:
            return MetricAssessment(GREEN, "Без потерь", "good")
        if value <= 1.5:
            return MetricAssessment(AMBER, "Единичные", "warning")
        return MetricAssessment(RED, "Потеря пакетов", "error")
    limits = {
        "dns": (25, 80, "Быстро", "Норма", "Медленно"),
        "ping": (45, 95, "Отлично", "Играбельно", "Высокий"),
        "jitter": (5, 15, "Стабильно", "Умеренно", "Скачки пинга"),
        "tcp": (50, 120, "Быстро", "Норма", "Задержка"),
    }
    low, high, good, warning, bad = limits[key]
    if value < low:
        return MetricAssessment(GREEN, good, "good")
    if value <= high:
        return MetricAssessment(AMBER, warning, "warning")
    return MetricAssessment(RED, bad, "error")


def is_external(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


def socket_priority(connection: object) -> int:
    if not is_external(connection.remote_address) or connection.remote_port < 1:
        return 3
    if connection.protocol.upper() == "UDP":
        return 0
    if (
        connection.protocol.upper() == "TCP"
        and connection.status.upper() == "ESTABLISHED"
        and connection.remote_port in (80, 443)
    ):
        return 1
    return 2


def is_literal_target(host: str) -> bool:
    from urllib.parse import urlsplit

    try:
        ipaddress.ip_address(host.strip().strip("[]"))
    except ValueError:
        try:
            parsed = urlsplit(host if "://" in host else "//" + host)
            ipaddress.ip_address(parsed.hostname or "")
        except ValueError:
            return False
    return True


def target_mode(host: str, protocol: str) -> str:
    if protocol.upper() == "UDP":
        return "Режим UDP: проверяем маршрут, пинг, джиттер и потери до сервера"
    if not is_literal_target(host):
        return "Режим TCP: проверяем задержку, доступность порта и TLS-сертификат"
    return "Режим TCP по IP: проверяем задержку и порт (TLS-сертификат требует домен)"


def socket_label(connection: object, translate=lambda text: text) -> str:
    proto = connection.protocol.upper()
    endpoint = connection.remote_endpoint
    if not is_external(connection.remote_address):
        return f"{proto} · {endpoint} ({translate('Локальный')})"
    if proto == "UDP":
        return f"🎮 UDP · {endpoint} ({translate('Игровой / Голос')})"
    suffix = f" ({translate('Веб / HTTPS')})" if connection.remote_port in (80, 443) else ""
    return f"🌐 {proto} · {endpoint}{suffix}"


def nat_description(value: str | None) -> str:
    kind = (value or "").casefold()
    if kind == "eim":
        return "Открытый / Умеренный — подходит для игр и голоса"
    if kind in {"edm", "apdm", "symmetric"}:
        return "Строгий NAT — возможны проблемы с P2P и лобби"
    return "Не определён"


def smart_verdict(
    gateway_ping: float | None,
    gateway_loss: float | None,
    vpn: bool,
    loss: float | None,
    jitter: float | None,
    ping: float | None,
    bare_ip_tls_only: bool = False,
) -> str:
    if (gateway_ping is not None and gateway_ping > GATEWAY_WARNING_MS) or (
        gateway_loss is not None and gateway_loss > 0
    ):
        return "Проблема локально (Wi-Fi / роутер) — проверьте сигнал или кабель"
    if gateway_ping is None and gateway_loss is None:
        if (loss is not None and loss > 1) or (jitter is not None and jitter > JITTER_WARNING_MS):
            return "Потери или скачки пинга — шлюз не проверен"
        return "Состояние шлюза не проверено"
    if vpn and (
        (loss is not None and loss > 1)
        or (jitter is not None and jitter > JITTER_WARNING_MS)
        or (ping is not None and ping > 95)
    ):
        return "Влияние VPN-туннеля — попробуйте сменить сервер VPN или включить Split-Tunneling"
    if not vpn and (
        (loss is not None and loss > 1) or (jitter is not None and jitter > JITTER_WARNING_MS)
    ):
        return "Проблема на маршруте провайдера или сервера — проверьте вкладку MTR"
    if bare_ip_tls_only:
        return "Связь стабильна (TLS не проверяется для голого IP)"
    return "Связь стабильна"
