"""Shared user interface configuration."""

METRIC_TOOLTIPS = {
    "dns": "Перевод имени в адрес. Показывает, насколько быстро компьютер находит IP-адрес сайта.",
    "ping": "Скорость отклика. Время в миллисекундах, за которое сигнал долетает до сервера и возвращается обратно.",
    "loss": "Пропавшие данные. Процент запросов без ответа. 100% потерь часто означают, что сайт просто скрывает пинг (ICMP).",
    "jitter": "Стабильность связи. Разброс времени отклика. Высокий Jitter вызывает зависания в играх и звонках.",
    "tcp": "Проверка порта. Показывает, открыт ли конкретный вход на сервере (например, 443 для HTTPS).",
    "tls": "Защищенность. Проверка шифрования и действительности защитного сертификата сайта.",
}

QUICK_PRESETS = (
    ("Google", "google.com", 443),
    ("Telegram", "t.me", 443),
    ("Яндекс", "yandex.ru", 443),
    ("Игровой сервер", "steamcommunity.com", 443),
)


CYBER_LIGHT_OVERRIDES = """
QMainWindow, QWidget#MainBg { background-color: #F3F6FA; color: #172033; }
QFrame#Sidebar { background-color: #FFFFFF; border-right-color: #D8E1EE; }
QFrame#Card, QFrame#MiniCard { background-color: #FFFFFF; border-color: #D8E1EE; }
QLabel#CardTitle, QLabel#MetricValue { color: #172033; }
QLabel#SubLabel, QLabel#DashboardFieldLabel, QLabel#MetricTitle { color: #64748B; }
QLabel#TopologySummary { color: #0E7490; }
QLabel#StatusPill { background-color: #EEF3F8; color: #475569; border-color: #CBD5E1; }
QLabel#StatusPill[healthState="good"] { background-color: #DCFCE7; color: #047857; border-color: #34D399; }
QLabel#StatusPill[healthState="warning"] { background-color: #FEF3C7; color: #B45309; border-color: #FBBF24; }
QLabel#StatusPill[healthState="error"] { background-color: #FFE4E6; color: #BE123C; border-color: #FB7185; }
QLineEdit#DashboardInput, QSpinBox#DashboardPort, QComboBox#DashboardCombo { background-color: #FFFFFF; color: #172033; border-color: #CBD5E1; }
QPushButton#NavBtn { color: #475569; }
QPushButton#NavBtn:hover { background-color: #E8F6FA; color: #0E7490; }
QPushButton#NavBtn:checked { background-color: #DFF6FB; color: #0E7490; border-color: #67E8F9; }
QFrame#SidebarTools { background-color: #E8F0F8; border-color: #CBD5E1; }
QPushButton#SideActionBtn, QFrame#SidebarTools QComboBox#LanguageSelector, QFrame#SidebarTools QToolButton#ThemeToggle { background-color: #FFFFFF; color: #334155; border-color: #CBD5E1; }
QFrame#SidebarTools QComboBox#LanguageSelector:hover, QFrame#SidebarTools QComboBox#LanguageSelector:focus, QFrame#SidebarTools QToolButton#ThemeToggle:hover { background-color: #F0F9FB; border-color: #67E8F9; color: #0E7490; }
QTableWidget { color: #1E293B; }
QTableWidget::item { border-bottom-color: #E2E8F0; }
QPlainTextEdit#DashboardEventLog { color: #475569; }
QHeaderView::section { color: #64748B; border-bottom-color: #E2E8F0; }
"""

DASHBOARD_SPLITTER_STATE_KEY = "UI/dashboard_splitter_state"

DASHBOARD_SPLITTER_DEFAULT_SIZES = (390, 290, 130)

DASHBOARD_TOP_ROW_SPLITTER_STATE_KEY = "UI/dashboard_top_row_splitter"

DASHBOARD_TOP_ROW_SPLITTER_DEFAULT_SIZES = (240, 520, 250)

DASHBOARD_TOP_ZONE_MINIMUM_HEIGHT = 440

DASHBOARD_HOP_HISTORY_SAMPLES = 60

WORKSPACE_TABS = {
    "routes": 1,
    "traceroute": 2,
    "interfaces": 3,
    "udp": 4,
    "journal": 4,
    "diagnosis": 5,
}

QUALITY_SOURCE_TABS = (6, 7, 8)

QUALITY_TABS = {"quality": 0, "bufferbloat": 1, "history": 2, "tls": 3}


DASHBOARD_HEADER_STATE_ICONS = {"good": "●", "info": "ℹ", "warning": "⚠", "error": "⛔"}

DASHBOARD_STATUS_COLORS = {
    "idle": ("#0B0E14", "#00E5A3", "#00F5B4"),
    "running": ("#FFB800", "#2A2110", "#806000"),
    "success": ("#0B0E14", "#00E5A3", "#00F5B4"),
    "warning": ("#FFB800", "#2A2110", "#806000"),
    "error": ("#FF4757", "#2A1218", "#8F2633"),
}

DASHBOARD_STATUS_HEALTH_LABELS = {
    "idle": "🟢  Сеть работает отлично",
    "running": "🟡  Есть задержки / Высокий пинг",
    "success": "🟢  Сеть работает отлично",
    "warning": "🟡  Есть задержки / Высокий пинг",
    "error": "🔴  Нет подключения",
}

DASHBOARD_QUICK_FIX_DEFINITIONS = (
    ("dns", "🔄  Сбросить кэш DNS", True),
    ("mtu", "📐  Оптимизировать MTU", False),
    ("stack", "🧰  Сбросить TCP/IP", False),
    ("adapter", "🔌  Перезапустить адаптер", False),
)

DASHBOARD_EXPORT_SECTION_LABELS = (
    ("report", "Диагностический отчёт"),
    ("session", "Журнал текущей сессии и пороги"),
    ("measurements", "Последние измерения"),
    ("process", "Выбранный процесс и endpoints"),
    ("history", "История тестов"),
)

DASHBOARD_PING_STAT_TITLES = (
    ("min RTT", "ping_stat_min"),
    ("max RTT", "ping_stat_max"),
    ("средний RTT", "ping_stat_average"),
    ("jitter", "ping_stat_jitter"),
    ("потери", "ping_stat_loss"),
    ("стабильность", "ping_stat_stability"),
)

DASHBOARD_JITTER_IMPACT_VALUES = (
    ("ТЕКУЩИЙ JITTER", "current"),
    ("MAX Δ RTT", "maximum"),
    ("MICRO-SPIKE", "spikes"),
    ("VOIP / ЗВОНКИ", "voice"),
    ("СОРЕВНОВАТЕЛЬНЫЕ ИГРЫ", "gaming"),
    ("СТАБИЛЬНОСТЬ", "stability"),
)

DASHBOARD_TLS_OVERVIEW_VALUES = (
    ("TCP CONNECT", "tcp_connect"),
    ("TLS HANDSHAKE", "handshake"),
    ("ПРОТОКОЛ", "protocol"),
    ("ШИФР", "cipher"),
    ("СЕРТИФИКАТ", "certificate"),
    ("ДО ОКОНЧАНИЯ", "expiry"),
)

DASHBOARD_QUALITY_DETAIL_ITEMS = (
    ("ipv4", "Внешний IPv4"),
    ("ipv6", "Внешний IPv6"),
    ("local_ip", "Локальный IP"),
    ("isp", "Провайдер"),
    ("location", "Регион / город"),
    ("vpn_proxy", "VPN / прокси"),
    ("adapter", "Адаптер / скорость"),
)

DASHBOARD_BUFFERBLOAT_PHASE_ITEMS = (
    ("unloaded", "Базовая задержка", "Пинг в покое"),
    ("download", "Скачивание под нагрузкой", "Задержка · скорость"),
    ("upload", "Отдача под нагрузкой", "Задержка · скорость"),
)

DASHBOARD_BUFFERBLOAT_SOURCES = (
    "Базовая задержка",
    "Скачивание под нагрузкой",
    "Отдача под нагрузкой",
)

DASHBOARD_LOSS_STAT_TITLES = (
    ("окно", "loss_stat_window"),
    ("получено", "loss_stat_received"),
    ("потери", "loss_stat_percent"),
    ("текущий burst", "loss_stat_current_burst"),
    ("max burst", "loss_stat_longest_burst"),
    ("jitter-события", "loss_stat_jitter_drops"),
)

DASHBOARD_NETWORK_METRIC_TITLES = (
    ("TCP CONNECT", "tcp_handshake_connect"),
    ("SYN", "tcp_handshake_syn"),
    ("SYN-ACK", "tcp_handshake_syn_ack"),
    ("ACK", "tcp_handshake_ack"),
    ("СТАТУС", "tcp_handshake_status"),
)

DASHBOARD_DASHBOARD_NAV_DEFINITIONS = (
    ("overview", "Обзор и диагноз"),
    ("routes", "Маршруты / Geo"),
    ("traceroute", "Трассировка / MTR"),
    ("interfaces", "Интерфейсы"),
    ("quality", "Качество и Bufferbloat"),
    ("journal", "Журнал и UDP"),
)

DASHBOARD_DASHBOARD_METRIC_DEFINITIONS = (
    ("dns", "DNS", "#34D399"),
    ("ping", "PING", "#22D3EE"),
    ("loss", "ПОТЕРИ", "#A855F7"),
    ("jitter", "ДЖИТТЕР", "#FBBF24"),
    ("tcp", "TCP", "#34D399"),
    ("tls", "TLS", "#22D3EE"),
)

DASHBOARD_NEUTRAL_METRICS = {
    "dns": "—",
    "ping": "— ms",
    "loss": "—",
    "jitter": "— ms",
    "tcp": "—",
    "tls": "—",
}

DASHBOARD_HEALTH_STATE_MAPPING = {
    "good": ("СВЯЗЬ СТАБИЛЬНА", "good"),
    "success": ("СВЯЗЬ СТАБИЛЬНА", "good"),
    "info": ("ВЫПОЛНЯЕТСЯ ПРОВЕРКА", "neutral"),
    "warning": ("ТРЕБУЕТСЯ ВНИМАНИЕ", "warning"),
    "error": ("ОБНАРУЖЕНА ПРОБЛЕМА", "error"),
    "running": ("ВЫПОЛНЯЕТСЯ ПРОВЕРКА", "neutral"),
}

DASHBOARD_TRAY_VISIBILITY_OPTIONS = ("--", "--", "--", "--")

DASHBOARD_TCP_PRESET_PORTS = (80, 443, 3389)
