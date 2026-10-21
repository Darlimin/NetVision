APP_STYLE = """
QWidget {
    color: #E1E7EF;
    background-color: #0D1117;
    font-family: "Inter", sans-serif;
    font-size: 12px;
}

QPushButton, QToolButton, QLineEdit, QSpinBox, QComboBox, QTableWidget,
QListWidget, QPlainTextEdit, QLabel, QHeaderView {
    font-family: "Inter", sans-serif;
}

QMainWindow, QDialog, QWidget#AppSurface, QStackedWidget {
    background-color: #0D1117;
}

QLabel {
    background-color: transparent;
}

QFrame {
    background: transparent;
    border: 0;
}

QFrame#Header, QFrame#ControlBar, QFrame#MetricTile, QFrame#SidePanel {
    background-color: #161B22;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 6px;
}

QFrame#DnsWorkspace, QFrame#DnsSystemPanel, QFrame#DnsInfoPanel,
QFrame#DnsAdapterPanel, QFrame#PingWorkspace,
QFrame#PingStatsPanel, QFrame#PingMatrixPanel, QFrame#PingSpikePanel,
QFrame#PingMtuPanel, QFrame#LossWorkspace, QFrame#LossStatsPanel,
QFrame#LossDetectorPanel, QFrame#LossStressPanel, QFrame#LossHopsPanel,
QFrame#TcpWorkspace, QFrame#TcpMetricsPanel, QFrame#TcpPortsPanel,
QFrame#TcpSocketsPanel, QFrame#TlsWorkspace, QFrame#TlsOverviewPanel,
QFrame#TlsToolsPanel, QFrame#TlsHandshakePanel, QFrame#TlsCertificatePanel,
QFrame#JitterWorkspace, QFrame#JitterImpactPanel, QFrame#JitterGraphPanel,
QFrame#JitterEventsPanel, QFrame#NetworkBoostDialogPanel,
QFrame#GeoHideDialogPanel, QFrame#GeoHideTitleBar {
    background-color: #161B22;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 6px;
}

QPushButton#GeoHideExpandButton, QPushButton#GeoHideCloseButton {
    min-width: 30px;
    min-height: 26px;
    padding: 0;
    color: #A0AEC0;
    background-color: #18202E;
    border: 1px solid #1E2638;
    border-radius: 4px;
    font-size: 15px;
    font-weight: 700;
}

QPushButton#GeoHideExpandButton:hover {
    color: #0B0E14;
    background-color: #00E5A3;
    border-color: #00F5B4;
}

QPushButton#GeoHideCloseButton:hover {
    color: #FFFFFF;
    background-color: #C43D4C;
    border-color: #FF4757;
}

QFrame#MetricTile[clickable="true"]:hover {
    background-color: #182C32;
    border-color: #00E5A3;
}

QFrame#MetricTile[clickable="true"] QLabel#MetricLabel {
    color: #00E5A3;
}

QLabel#DnsWorkspaceTitle, QLabel#PingWorkspaceTitle {
    color: #E2E8F0;
    font-size: 16pt;
    font-weight: 700;
}

QLabel#LossWorkspaceTitle {
    color: #E2E8F0;
    font-size: 16pt;
    font-weight: 700;
}

QLabel#TcpWorkspaceTitle {
    color: #E2E8F0;
    font-size: 16pt;
    font-weight: 700;
}

QLabel#TlsWorkspaceTitle {
    color: #E2E8F0;
    font-size: 16pt;
    font-weight: 700;
}

QLabel#JitterWorkspaceTitle {
    color: #E2E8F0;
    font-size: 16pt;
    font-weight: 700;
}

QPushButton#DnsBackButton, QPushButton#DnsApplyButton, QPushButton#DnsAdapterPropertiesButton, QPushButton#PingBackButton,
QPushButton#PingSecondaryButton, QPushButton#LossBackButton, QPushButton#TcpBackButton,
QPushButton#TcpSecondaryButton, QPushButton#TlsBackButton,
QPushButton#TlsSecondaryButton, QPushButton#JitterBackButton,
QPushButton#JitterSecondaryButton, QPushButton#NetworkBoostButton,
QPushButton#NetworkBoostCancelButton, QPushButton#LossAutoCheckButton {
    min-height: 32px;
    padding: 0 12px;
    color: #A0AEC0;
    background-color: #18202E;
    border: 1px solid #1E2638;
    border-radius: 5px;
    font-weight: 600;
}

QPushButton#DnsBackButton:hover, QPushButton#DnsApplyButton:hover, QPushButton#DnsAdapterPropertiesButton:hover,
QPushButton#PingBackButton:hover, QPushButton#PingSecondaryButton:hover,
QPushButton#LossBackButton:hover, QPushButton#TcpBackButton:hover,
QPushButton#TcpSecondaryButton:hover, QPushButton#TlsBackButton:hover,
QPushButton#TlsSecondaryButton:hover, QPushButton#JitterBackButton:hover,
QPushButton#JitterSecondaryButton:hover, QPushButton#NetworkBoostButton:hover,
QPushButton#NetworkBoostCancelButton:hover, QPushButton#LossAutoCheckButton:hover {
    color: #E1E7EF;
    background-color: #222C3D;
    border-color: #00E5A3;
}

QPushButton#DnsInfoChip {
    min-height: 50px;
    padding: 7px 10px;
    color: #C8D0DC;
    background-color: #18202E;
    border: 1px solid #1E2638;
    border-radius: 5px;
    font-family: "Inter", sans-serif;
    font-size: 13px;
    font-weight: 600;
    text-align: left;
}

QPushButton#DnsInfoChip:hover {
    color: #E1E7EF;
    background-color: #1C2A36;
    border-color: #00E5A3;
}

QPushButton#ProcessCaptureButton, QPushButton#ManualProcessButton {
    min-height: 32px;
    padding: 0 10px;
    color: #A0AEC0;
    background-color: #18202E;
    border: 1px solid #1E2638;
    border-radius: 5px;
    font-family: "Inter", sans-serif;
    font-size: 12px;
    font-weight: 600;
}

QPushButton#ProcessCaptureButton:hover, QPushButton#ManualProcessButton:hover {
    color: #E1E7EF;
    background-color: #222C3D;
    border-color: #00E5A3;
}

QSplitter#WorkspaceSplitter::handle {
    background-color: #1E2638;
}

QSplitter#WorkspaceSplitter::handle:hover {
    background-color: #00C98D;
}

QSplitter#WorkspaceSplitter::handle:horizontal {
    width: 5px;
    margin: 2px 3px;
}

QSplitter#WorkspaceSplitter::handle:vertical {
    height: 10px;
    margin: 0;
}

QDialog#GameAutoCheckDialog {
    background-color: #0D1117;
}

QFrame#GameAutoCheckCard {
    background-color: #161B22;
    border: 1px solid #1E2638;
    border-radius: 6px;
}

QLabel#GameAutoCheckTitle {
    color: #E2E8F0;
    font-size: 15pt;
    font-weight: 700;
}

QLabel#GameAutoCheckVersion {
    color: #8A99AD;
    font-size: 11px;
    font-weight: 600;
}

QLabel#GameAutoCheckValue {
    color: #00E5A3;
    font-size: 13px;
    font-weight: 700;
}

QLabel#GameAutoCheckStatus {
    color: #8A99AD;
    padding: 4px 8px;
    border-radius: 4px;
}

QLabel#GameAutoCheckStatus[alertState="good"] { color: #00E5A3; background-color: #12352D; }
QLabel#GameAutoCheckStatus[alertState="warning"] { color: #FFB800; background-color: #382E18; }
QLabel#GameAutoCheckStatus[alertState="error"] { color: #FF6B78; background-color: #3A2027; }

QTableWidget#GameAutoCheckHistoryTable {
    background-color: #111722;
    border: 1px solid #1E2638;
    border-radius: 5px;
    alternate-background-color: #161E2B;
}

QPushButton#ConnectionSortButton {
    min-width: 154px;
    min-height: 32px;
    padding: 0 10px;
    color: #A0AEC0;
    background-color: #18202E;
    border: 1px solid #1E2638;
    border-radius: 5px;
    font-family: "Inter", sans-serif;
    font-size: 12px;
    font-weight: 600;
}

QPushButton#ConnectionSortButton:hover {
    color: #E1E7EF;
    background-color: #222C3D;
    border-color: #00E5A3;
}

QPushButton#ConnectionSortButton[sortMode="1"] {
    color: #0B0E14;
    background-color: #00E5A3;
    border-color: #00F5B4;
}

QPushButton#ConnectionSortButton[sortMode="2"] {
    color: #FFC0C5;
    background-color: #2B1B22;
    border-color: #FF4757;
}

QPushButton#DnsInfoChip:disabled {
    color: #78869A;
    background-color: #131822;
    border-color: #1E2638;
}

QPushButton#DnsRunButton, QPushButton#PingRunButton {
    min-height: 34px;
    padding: 0 14px;
    color: #0B0E14;
    background-color: #00E5A3;
    border: 1px solid #00F5B4;
    border-radius: 5px;
    font-weight: 700;
}

QPushButton#LossRunButton {
    min-height: 34px;
    padding: 0 14px;
    color: #0B0E14;
    background-color: #00E5A3;
    border: 1px solid #00F5B4;
    border-radius: 5px;
    font-weight: 700;
}

QPushButton#TcpRunButton {
    min-height: 34px;
    padding: 0 14px;
    color: #0B0E14;
    background-color: #00E5A3;
    border: 1px solid #00F5B4;
    border-radius: 5px;
    font-weight: 700;
}

QPushButton#TlsRunButton {
    min-height: 34px;
    padding: 0 14px;
    color: #0B0E14;
    background-color: #00E5A3;
    border: 1px solid #00F5B4;
    border-radius: 5px;
    font-weight: 700;
}

QPushButton#JitterRunButton {
    min-height: 34px;
    padding: 0 14px;
    color: #0B0E14;
    background-color: #00E5A3;
    border: 1px solid #00F5B4;
    border-radius: 5px;
    font-weight: 700;
}

QPushButton#NetworkBoostTerminateButton {
    min-height: 34px;
    padding: 0 14px;
    color: #0B0E14;
    background-color: #00E5A3;
    border: 1px solid #00F5B4;
    border-radius: 5px;
    font-weight: 700;
}

QPushButton#DnsRunButton:hover, QPushButton#PingRunButton:hover {
    background-color: #00F5B4;
}

QPushButton#LossRunButton:hover {
    background-color: #00F5B4;
}

QPushButton#TcpRunButton:hover {
    background-color: #00F5B4;
}

QPushButton#TlsRunButton:hover {
    background-color: #00F5B4;
}

QPushButton#JitterRunButton:hover {
    background-color: #00F5B4;
}

QPushButton#NetworkBoostTerminateButton:hover {
    background-color: #00F5B4;
}

QPushButton#NetworkBoostTerminateButton:disabled {
    color: #78869A;
    background-color: #18202E;
    border-color: #1E2638;
}

QLabel#NetworkBoostDialogTitle {
    color: #E2E8F0;
    font-size: 15pt;
    font-weight: 700;
}

QLabel#NetworkBoostDialogStatus {
    color: #8A99AD;
    background-color: #111622;
    border: 1px solid #1E2638;
    border-radius: 5px;
    padding: 8px 10px;
}

QCheckBox#NetworkBoostCandidate {
    color: #E1E7EF;
    background-color: #18202E;
    border: 1px solid #1E2638;
    border-radius: 5px;
    padding: 9px 10px;
    spacing: 9px;
}

QCheckBox#NetworkBoostCandidate:hover {
    background-color: #222C3D;
    border-color: #00E5A3;
}

QCheckBox#NetworkBoostCandidate:disabled {
    color: #78869A;
    border-color: #1E2638;
}

QTableWidget#DnsBenchmarkTable, QTableWidget#PingMatrixTable, QTableWidget#PingMtuTable {
    alternate-background-color: #131B25;
    selection-background-color: #124F43;
}

QTableWidget#LossStressTable, QTableWidget#LossHopsTable {
    alternate-background-color: #131B25;
    selection-background-color: #124F43;
}

QTableWidget#TcpPortsTable, QTableWidget#TcpSocketsTable {
    alternate-background-color: #131B25;
    selection-background-color: #124F43;
}

QTableWidget#TlsHandshakeTable, QTableWidget#TlsCertificateTable {
    alternate-background-color: #131B25;
    selection-background-color: #124F43;
}

QTableWidget#JitterEventsTable {
    alternate-background-color: #131B25;
    selection-background-color: #124F43;
}

QLabel#PingStatValue {
    color: #00E5A3;
    font-family: "Inter", sans-serif;
    font-size: 13px;
    font-weight: 700;
}

QLabel#LossStatValue {
    color: #00E5A3;
    font-family: "Inter", sans-serif;
    font-size: 13px;
    font-weight: 700;
}

QLabel#TcpMetricValue {
    color: #00E5A3;
    font-family: "Inter", sans-serif;
    font-size: 13px;
    font-weight: 700;
}

QLabel#TlsMetricValue {
    color: #00E5A3;
    font-family: "Inter", sans-serif;
    font-size: 13px;
    font-weight: 700;
}

QLabel#TlsMetricValue[state="warning"] {
    color: #FFB800;
}

QLabel#TlsMetricValue[state="bad"] {
    color: #FF4757;
}

QLabel#TlsMetricValue[state="neutral"] {
    color: #78869A;
}

QLabel#JitterMetricValue {
    color: #00E5A3;
    font-family: "Inter", sans-serif;
    font-size: 13px;
    font-weight: 700;
}

QLabel#JitterMetricValue[state="warning"] {
    color: #FFB800;
}

QLabel#JitterMetricValue[state="bad"] {
    color: #FF4757;
}

QLabel#JitterMetricValue[state="neutral"] {
    color: #78869A;
}

QPlainTextEdit#PingSpikeLog {
    color: #C8D0DC;
    background-color: #111722;
    border: 1px solid #1E2638;
    border-radius: 5px;
    font-family: "Inter", sans-serif;
    font-size: 11px;
}

QPlainTextEdit#LossEventsLog {
    color: #C8D0DC;
    background-color: #111722;
    border: 1px solid #1E2638;
    border-radius: 5px;
    font-family: "Inter", sans-serif;
    font-size: 11px;
}

QScrollArea#PingWorkspaceScroll {
    background: transparent;
    border: 0;
}

QScrollArea#LossWorkspaceScroll {
    background: transparent;
    border: 0;
}

QScrollArea#TcpWorkspaceScroll {
    background: transparent;
    border: 0;
}

QScrollArea#TlsWorkspaceScroll {
    background: transparent;
    border: 0;
}

QScrollArea#JitterWorkspaceScroll {
    background: transparent;
    border: 0;
}

QFrame#QuickActions, QFrame#ProcessInspectorBar {
    background-color: #161B22;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 6px;
}

QFrame#QuickFixPanel {
    background-color: #131822;
    border: 1px solid #1E2638;
    border-radius: 6px;
}

QLabel#QuickFixTitle {
    color: #E2E8F0;
    font-size: 11px;
    font-weight: 700;
}

QLabel#QuickFixStatus {
    color: #8A99AD;
    font-size: 11px;
}

QPushButton#QuickFixButton, QPushButton#QuickFixPrimary {
    min-height: 34px;
    padding: 0 12px;
    color: #A0AEC0;
    background-color: #18202E;
    border: 1px solid #1E2638;
    border-radius: 5px;
    font-weight: 600;
}

QPushButton#QuickFixButton:hover {
    color: #E1E7EF;
    background-color: #222C3D;
    border-color: #00E5A3;
}

QPushButton#QuickFixPrimary {
    color: #0B0E14;
    background-color: #00E5A3;
    border-color: #00F5B4;
}

QPushButton#QuickFixPrimary:hover {
    background-color: #00F5B4;
}

QProgressBar#QualityProgress {
    border: 0;
    border-radius: 3px;
    background-color: #18202E;
}

QProgressBar#QualityProgress::chunk {
    border-radius: 3px;
    background-color: #00E5A3;
}

QFrame#BufferbloatPhaseCard, QFrame#BufferbloatGrade {
    background-color: #171D27;
    border: 1px solid #263244;
    border-radius: 8px;
}

QLabel#BufferbloatValue {
    color: #00E5A3;
    font-size: 18px;
    font-weight: 700;
}

QLabel#BufferbloatGradeValue {
    color: #00E5A3;
    font-size: 30px;
    font-weight: 700;
}

QProgressBar#BufferbloatProgress {
    border: 0;
    border-radius: 3px;
    background-color: #18202E;
}

QProgressBar#BufferbloatProgress::chunk {
    border-radius: 3px;
    background-color: #00E5A3;
}

QComboBox {
    min-height: 28px;
    padding: 0 8px;
    color: #E1E7EF;
    background-color: #18202E;
    border: 1px solid #1E2638;
    border-radius: 5px;
}

QComboBox:hover, QComboBox:focus {
    border-color: #00E5A3;
}

QComboBox#LanguageSelector {
    min-height: 32px;
    max-height: 32px;
    padding: 0 22px 0 8px;
    color: #A0AEC0;
    background-color: #18202E;
    border: 1px solid #1E2638;
    border-radius: 5px;
    font-size: 10px;
    font-weight: 700;
}

QComboBox#LanguageSelector:hover, QComboBox#LanguageSelector:focus {
    color: #E1E7EF;
    border-color: #00E5A3;
}

QToolButton#ThemeToggle {
    min-width: 36px;
    min-height: 36px;
    max-width: 36px;
    max-height: 36px;
    padding: 0;
    color: #A0AEC0;
    background-color: #18202E;
    border: 1px solid #1E2638;
    border-radius: 18px;
    font-size: 15px;
}

QToolButton#ThemeToggle:hover {
    color: #00E5A3;
    border-color: #00E5A3;
    background-color: #1A2B31;
}

QWidget#HeaderBrand, QWidget#HeaderIdentity, QWidget#HeaderSettings, QWidget#HeaderModeControls {
    background: transparent;
    border: 0;
}

QWidget#HeaderSettings QLabel#ModeLabel {
    min-width: 0;
}

QComboBox QAbstractItemView {
    color: #E1E7EF;
    background-color: #161B22;
    selection-background-color: #124F43;
}

QFrame#EmbeddedDropdown {
    background-color: #161B22;
    border: 1px solid #2A364A;
    border-radius: 6px;
}

QListWidget#EmbeddedDropdownList {
    color: #E1E7EF;
    background-color: transparent;
    border: 0;
    outline: 0;
}

QListWidget#EmbeddedDropdownList::item {
    min-height: 28px;
    padding: 2px 8px;
    border-radius: 4px;
}

QListWidget#EmbeddedDropdownList::item:hover,
QListWidget#EmbeddedDropdownList::item:selected {
    color: #E1E7EF;
    background-color: #182C32;
}

QLabel#LatencyTooltip {
    min-width: 0;
    min-height: 0;
    padding: 5px 8px;
    color: #E1E7EF;
    background-color: #111622;
    border: 1px solid rgba(255, 255, 255, 0.10);
    border-radius: 6px;
    font-size: 12px;
}

QLabel#ModeLabel {
    color: #8A99AD;
    font-size: 10px;
    font-weight: 700;
}

QRadioButton#ModeToggle {
    min-height: 28px;
    padding: 4px 8px;
    color: #8A99AD;
    background-color: #18202E;
    border: 1px solid #1E2638;
    border-radius: 5px;
    font-size: 10px;
    font-weight: 700;
}

QRadioButton#ModeToggle::indicator {
    width: 0;
    height: 0;
}

QRadioButton#ModeToggle:checked {
    color: #0B0E14;
    background-color: #00E5A3;
    border-color: #00F5B4;
}

QFrame#LiteSummaryPanel {
    background-color: transparent;
    border: 0;
}

QLabel#MonospaceValue {
    font-family: "Inter", sans-serif;
    font-size: 9pt;
    color: #E2E8F0;
}

QFrame#LiteHeroCard {
    background-color: #161B22;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 8px;
}

QLabel#LiteTitle {
    color: #E2E8F0;
    font-size: 19pt;
    font-weight: 700;
    background-color: transparent;
}

QWidget#LatencyChart, QWidget#JitterChart {
    background-color: #161B22;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 6px;
}

QScrollArea#TopologyScrollArea, QScrollArea#DetailsScrollArea {
    background: transparent;
    border: 0;
}

QLabel#LiteMessage {
    color: #E2E8F0;
    font-size: 11pt;
    background-color: transparent;
}

QLabel#LiteCause {
    max-width: 860px;
    padding: 9px 12px;
    color: #E2E8F0;
    background-color: #18202E;
    border-left: 3px solid #FFB800;
    border-radius: 4px;
    font-size: 10pt;
}

QLabel#AnalysisTitle {
    color: #E2E8F0;
    font-size: 15pt;
    font-weight: 650;
}

QLabel#LiteDetail {
    min-height: 32px;
    padding: 7px 12px;
    color: #E2E8F0;
    background-color: #18202E;
    border: 1px solid #1E2638;
    border-radius: 5px;
    font-size: 10pt;
}

QLabel#LiteDetailCard {
    min-height: 70px;
    padding: 10px 12px;
    color: #E2E8F0;
    background-color: #161B22;
    border: 1px solid #1E2638;
    border-radius: 6px;
    font-size: 10pt;
    font-weight: 600;
}

QLabel#LiteDetailCard[cardState="good"] {
    border-left: 4px solid #00E5A3;
}

QLabel#LiteDetailCard[cardState="bad"] {
    border-left: 4px solid #FF4757;
}

QLabel#LiteDetailCard[cardState="neutral"] {
    border-left: 4px solid #78869A;
}

QToolButton#MetricHelpButton {
    min-width: 20px;
    min-height: 20px;
    max-width: 20px;
    max-height: 20px;
    padding: 0;
    color: #8A99AD;
    background-color: #18202E;
    border: 1px solid #1E2638;
    border-radius: 10px;
    font-size: 8pt;
    font-weight: 700;
}

QToolButton#MetricHelpButton:hover {
    color: #00E5A3;
    border-color: #00E5A3;
}

QLabel#QuickActionsTitle {
    min-width: 118px;
    color: #E2E8F0;
    font-size: 10px;
    font-weight: 700;
}

QLabel#ProcessSelectorLabel {
    min-width: 82px;
    color: #E2E8F0;
    font-family: "Inter", sans-serif;
    font-size: 10px;
    font-weight: bold;
}

QPushButton#QuickActionButton {
    min-height: 32px;
    padding-left: 12px;
    padding-right: 12px;
    color: #A0AEC0;
    background-color: #18202E;
    border: 1px solid #1E2638;
    border-radius: 5px;
    font-weight: 600;
}

QPushButton#QuickActionButton:hover {
    color: #E1E7EF;
    border-color: #00E5A3;
    background-color: #222C3D;
}

QPushButton#QuickActionButton:pressed {
    background-color: #124F43;
}

QPushButton#QuickActionButton:disabled {
    color: #5B6B82;
    background-color: #131822;
    border-color: #1E2638;
}

QPushButton#QuickActionPrimary {
    min-height: 32px;
    padding-left: 12px;
    padding-right: 12px;
    color: #0B0E14;
    background-color: #00E5A3;
    border: 1px solid #00F5B4;
    border-radius: 5px;
    font-weight: 700;
}

QPushButton#QuickActionPrimary:hover {
    background-color: #00F5B4;
    border-color: #68FFD1;
}

QPushButton#QuickActionPrimary:pressed {
    background-color: #00B982;
}

QPushButton#QuickActionPrimary:disabled {
    color: #5B6B82;
    background-color: #18202E;
    border-color: #1E2638;
}

QLabel#Brand {
    color: #E2E8F0;
    font-size: 20pt;
    font-weight: 700;
}

QLabel#BrandCaption, QLabel#Muted, QLabel#MetricLabel, QLabel#FieldLabel {
    color: #8A99AD;
}

QLabel#BrandCaption, QLabel#MetricLabel, QLabel#FieldLabel {
    font-size: 10px;
    font-weight: 600;
}

QLabel#UdpPortStatus {
    min-height: 18px;
    padding: 1px 2px;
    color: #8A99AD;
    background-color: transparent;
    font-family: "Inter", sans-serif;
    font-size: 11px;
}

QLabel#StatusBadge {
    color: #8A99AD;
    background-color: #18202E;
    border: 1px solid #1E2638;
    border-radius: 10px;
    padding: 4px 10px;
    font-size: 8pt;
    font-weight: 700;
}

QLabel#HealthIndicator {
    color: #7DE2D1;
    background-color: #102A26;
    border: 1px solid #257E72;
    border-radius: 10px;
    padding: 6px 12px;
    font-size: 9pt;
    font-weight: 700;
}

QPushButton#PresetButton {
    min-height: 30px;
    padding: 0 8px;
    color: #B9C7D4;
    background-color: #18202E;
    border: 1px solid #1E2638;
    border-radius: 5px;
    font-size: 8pt;
    font-weight: 600;
}

QPushButton#PresetButton:hover {
    color: #E1E7EF;
    border-color: #00E5A3;
    background-color: #1A2B31;
}

QPushButton#PresetButton:checked {
    color: #081411;
    background-color: #00E5A3;
    border-color: #00F5B4;
}

QLabel#MetricValue {
    color: #E2E8F0;
    font-size: 16pt;
    font-weight: 650;
}

QFrame#MetricTile[compact="true"] {
    min-height: 76px;
    max-height: 82px;
}

QFrame#MetricTile[compact="true"] QLabel#MetricValue {
    font-size: 13pt;
}

QFrame#MetricTile[compact="true"] QLabel#MetricVerdict {
    min-height: 16px;
    padding: 1px 3px;
    font-size: 12px;
}

QLabel#MetricValue[metricState="good"] {
    color: #2ECC71;
}

QLabel#MetricValue[metricState="bad"] {
    color: #E74C3C;
}

QLabel#MetricValue[metricState="neutral"] {
    color: #4A5568;
}

QLabel#MetricIcon {
    min-width: 18px;
    color: #E2E8F0;
    font-size: 10pt;
}

QLabel#MetricVerdict {
    min-height: 20px;
    padding: 2px 6px;
    color: #C8D0DC;
    background-color: transparent;
    border: 1px solid transparent;
    border-radius: 4px;
    font-size: 13px;
}

QLabel#MetricVerdict[waiting="true"] {
    color: #718096;
    background-color: rgba(113, 128, 150, 0.12);
    border: 1px solid rgba(138, 153, 173, 0.18);
}

QLineEdit, QSpinBox {
    min-height: 36px;
    padding: 0 10px;
    background-color: #18202E;
    border: 1px solid #1E2638;
    border-radius: 5px;
    selection-background-color: #177D72;
}

QLineEdit:focus, QSpinBox:focus {
    border-color: rgba(0, 229, 163, 0.30);
}

QPushButton {
    min-height: 36px;
    padding: 0 16px;
    border: 1px solid #00F5B4;
    border-radius: 5px;
    color: #081411;
    background-color: #00E5A3;
    font-weight: 700;
}

QPushButton:hover {
    background-color: #5EDCC9;
}

QPushButton:pressed {
    background-color: #2FB4A2;
}

QPushButton:disabled {
    color: #63717C;
    border-color: #1E2638;
    background-color: #18202E;
}

QToolButton {
    min-width: 34px;
    min-height: 34px;
    color: #A0AEC0;
    background-color: #18202E;
    border: 1px solid #1E2638;
    border-radius: 5px;
}

QToolButton:hover {
    color: #00E5A3;
    border-color: #00E5A3;
}

QToolButton:disabled {
    color: #63717C;
    background-color: #141B21;
    border-color: #27323A;
}

QFrame#SessionCapsule {
    min-height: 38px;
    background-color: #111922;
    border: 1px solid #243244;
    border-radius: 18px;
}

QToolButton#SessionTimerButton,
QToolButton#SessionResetButton,
QToolButton#SessionLogButton {
    min-height: 30px;
    color: #A0AEC0;
    background: transparent;
    border: 0;
}

QToolButton#SessionTimerButton {
    min-width: 90px;
    padding: 0 8px;
    color: #E1E7EF;
    font-family: "Inter", sans-serif;
    font-size: 11px;
    font-weight: 600;
    text-align: center;
}

QToolButton#SessionTimerButton[paused="true"] {
    color: #8A99AD;
}

QToolButton#SessionTimerButton:hover,
QToolButton#SessionResetButton:hover {
    color: #00E5A3;
    background-color: #182C32;
    border-radius: 14px;
}

QToolButton#SessionResetButton {
    min-width: 28px;
    max-width: 28px;
    padding: 0;
    font-size: 15px;
}

QToolButton#SessionLogButton {
    min-width: 0;
    padding: 0 10px;
    text-align: left;
    border-left: 1px solid #243244;
    font-size: 12px;
}

QToolButton#SessionLogButton:hover {
    background-color: #182C32;
    border-top-right-radius: 14px;
    border-bottom-right-radius: 14px;
}

QToolButton#SessionLogButton[anomalyState="good"] { color: #00E5A3; }
QToolButton#SessionLogButton[anomalyState="info"] { color: #8ACBFF; }
QToolButton#SessionLogButton[anomalyState="warning"] { color: #FFB800; }
QToolButton#SessionLogButton[anomalyState="error"] { color: #FF6370; }

QMenu#SessionAnomalyMenu {
    background-color: #131822;
    border: 1px solid #2A3A4D;
    border-radius: 8px;
    padding: 4px;
}

QFrame#SessionAnomalyMenuContent {
    background-color: #131822;
    border: 0;
}

QLabel#SessionAnomalyMenuTitle {
    color: #8A99AD;
    font-size: 10px;
    font-weight: 700;
    padding: 0 2px 3px 2px;
}

QLabel#SessionAnomalyItem {
    color: #C8D0DC;
    background-color: #18202E;
    border: 1px solid #263247;
    border-radius: 5px;
    padding: 7px 8px;
    font-size: 12px;
}

QLabel#SessionAnomalyItem[anomalyState="warning"] { border-left: 3px solid #FFB800; }
QLabel#SessionAnomalyItem[anomalyState="error"] { border-left: 3px solid #FF6370; }

QLabel#SessionAnomalyEmptyState {
    color: #8A99AD;
    padding: 10px 8px;
    font-size: 12px;
}

QPushButton#SessionAnomalyOpenLogButton {
    min-height: 30px;
    color: #0B0E14;
    background-color: #00E5A3;
    border: 1px solid #00E5A3;
    border-radius: 5px;
    padding: 0 10px;
    font-weight: 700;
}

QPushButton#SessionAnomalyOpenLogButton:hover {
    background-color: #5EDCC9;
    border-color: #5EDCC9;
}

QTabWidget::pane {
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 6px;
    background-color: #161B22;
    top: -1px;
}

QTabBar::tab {
    min-width: 86px;
    min-height: 30px;
    padding: 0 8px;
    color: #78869A;
    background-color: #0B0E14;
    border: 0;
    border-bottom: 2px solid transparent;
}

QTabBar::tab:first {
    border-top-left-radius: 5px;
}

QTabBar::tab:last {
    border-top-right-radius: 5px;
}

QTabBar::tab:selected {
    color: #E8EDF2;
    background-color: #18202E;
    border-bottom-color: #00E5A3;
}

QTabBar::tab:hover {
    color: #E2E8F0;
    background-color: #18202E;
}

QTableWidget, QPlainTextEdit {
    background-color: #18202E;
    border: 0;
    gridline-color: #202B34;
    alternate-background-color: #111A21;
    selection-background-color: #124F43;
}

QTableWidget {
    color: #D7E0E8;
    outline: 0;
}

QTableWidget::item {
    padding: 4px 8px;
    border-bottom: 1px solid #202B34;
}

QTableWidget::item:hover {
    background-color: #1B3937;
}

QHeaderView::section {
    color: #8A99AD;
    background-color: #131822;
    border: 0;
    border-right: 1px solid #2A2A2A;
    border-bottom: 1px solid #2A2A2A;
    padding: 5px 8px;
    font-size: 11px;
    font-weight: 700;
}

QHeaderView::section:hover {
    color: #E2E8F0;
    background-color: #182C32;
}

QTableWidget#UdpEventsTable {
    alternate-background-color: #131B25;
    selection-background-color: #124F43;
}

QCheckBox#UdpAnomalyFilter {
    min-height: 28px;
    padding: 0 8px;
    color: #A0AEC0;
    background-color: #18202E;
    border: 1px solid #1E2638;
    border-radius: 5px;
    font-weight: 600;
}

QCheckBox#UdpAnomalyFilter:hover {
    color: #E1E7EF;
    border-color: #00E5A3;
}

QCheckBox#UdpAnomalyFilter::indicator {
    width: 14px;
    height: 14px;
}

QCheckBox#UdpAnomalyFilter::indicator:checked {
    background-color: #00E5A3;
    border: 1px solid #00F5B4;
}

QHeaderView::section {
    min-height: 30px;
    padding: 5px 8px;
    color: #8A99AD;
    background-color: #131822;
    border: 0;
    border-right: 1px solid #2A2A2A;
    border-bottom: 1px solid #2A2A2A;
    font-size: 11px;
    font-weight: 700;
}

QScrollArea, QAbstractScrollArea {
    border: 0;
}

QScrollBar:vertical {
    width: 10px;
    margin: 2px;
    background: transparent;
}

QScrollBar::handle:vertical {
    min-height: 32px;
    border-radius: 4px;
    background: #34424E;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}

/* Busy buttons keep their text and 1px border so layouts never reflow. */
QPushButton[taskBusy="true"], QToolButton[taskBusy="true"] {
    color: #E1E7EF;
    background-color: #182C32;
    border: 1px solid #00E5A3;
}

QPushButton[taskBusy="true"][taskBusyPhase="0"],
QToolButton[taskBusy="true"][taskBusyPhase="0"] {
    border-color: #00E5A3;
    background-color: #182C32;
}

QPushButton[taskBusy="true"][taskBusyPhase="1"],
QToolButton[taskBusy="true"][taskBusyPhase="1"] {
    border-color: #75F8D7;
    background-color: #1B343B;
}

QPushButton[taskBusy="true"][taskBusyPhase="2"],
QToolButton[taskBusy="true"][taskBusyPhase="2"] {
    border-color: #129D7A;
    background-color: #172A31;
}

QToolTip {
    color: #E8EDF2;
    background-color: #18212A;
    border: 1px solid #394854;
    padding: 5px;
}
"""

# The light theme intentionally reuses the same geometry, spacing and green
# interaction states. Only surfaces, text and neutral borders change.
LIGHT_STYLE = APP_STYLE + """

QWidget {
    color: #1F2937;
    background-color: #F4F7F8;
}

QMainWindow, QDialog, QWidget#AppSurface, QStackedWidget {
    background-color: #F4F7F8;
}

QFrame#Header, QFrame#ControlBar, QFrame#MetricTile, QFrame#SidePanel,
QFrame#QuickActions, QFrame#ProcessInspectorBar, QFrame#LiteHeroCard,
QFrame#DnsWorkspace, QFrame#DnsSystemPanel, QFrame#DnsInfoPanel,
QFrame#DnsAdapterPanel, QFrame#PingWorkspace,
QFrame#PingStatsPanel, QFrame#PingMatrixPanel, QFrame#PingSpikePanel,
QFrame#PingMtuPanel, QFrame#LossWorkspace, QFrame#LossStatsPanel,
QFrame#LossDetectorPanel, QFrame#LossStressPanel, QFrame#LossHopsPanel,
QFrame#TcpWorkspace, QFrame#TcpMetricsPanel, QFrame#TcpPortsPanel,
QFrame#TcpSocketsPanel, QFrame#TlsWorkspace, QFrame#TlsOverviewPanel,
QFrame#TlsToolsPanel, QFrame#TlsHandshakePanel, QFrame#TlsCertificatePanel,
QFrame#JitterWorkspace, QFrame#JitterImpactPanel, QFrame#JitterGraphPanel,
QFrame#JitterEventsPanel, QFrame#NetworkBoostDialogPanel,
QFrame#GeoHideDialogPanel, QFrame#GeoHideTitleBar,
QFrame#QuickFixPanel,
QWidget#LatencyChart, QWidget#JitterChart {
    background-color: #FFFFFF;
    border-color: #D9E2E5;
}

QPushButton#GeoHideExpandButton, QPushButton#GeoHideCloseButton {
    color: #52606D;
    background-color: #EEF2F3;
    border-color: #D9E2E5;
}

QPushButton#GeoHideExpandButton:hover {
    color: #0B0E14;
    background-color: #00D9A0;
    border-color: #00B98A;
}

QPushButton#GeoHideCloseButton:hover {
    color: #FFFFFF;
    background-color: #D94B59;
    border-color: #C43D4C;
}

QLabel#Brand, QLabel#LiteTitle, QLabel#LiteMessage, QLabel#AnalysisTitle,
QLabel#QuickActionsTitle, QLabel#ProcessSelectorLabel, QLabel#MetricIcon,
QLabel#DnsWorkspaceTitle, QLabel#PingWorkspaceTitle, QLabel#LossWorkspaceTitle,
QLabel#TcpWorkspaceTitle, QLabel#TlsWorkspaceTitle, QLabel#JitterWorkspaceTitle,
QLabel#NetworkBoostDialogTitle {
    color: #17212B;
}

QLabel#BrandCaption, QLabel#Muted, QLabel#MetricLabel, QLabel#FieldLabel,
QLabel#ModeLabel, QLabel#UdpPortStatus {
    color: #667784;
}

QComboBox, QLineEdit, QSpinBox, QPlainTextEdit, QTableWidget,
QRadioButton#ModeToggle, QToolButton, QCheckBox#UdpAnomalyFilter,
QPushButton#QuickActionButton, QPushButton#PresetButton {
    color: #25313B;
    background-color: #FFFFFF;
    border-color: #C9D5D9;
}

QComboBox#LanguageSelector {
    color: #25313B;
    background-color: #FFFFFF;
    border-color: #C9D5D9;
}

QComboBox#LanguageSelector:hover, QComboBox#LanguageSelector:focus {
    color: #17212B;
    border-color: #00B982;
}

QToolButton#ThemeToggle {
    color: #25313B;
    background-color: #FFFFFF;
    border-color: #C9D5D9;
}

QToolButton#ThemeToggle:hover {
    color: #00A875;
    background-color: #EAF8F3;
    border-color: #00B982;
}

QPushButton#DnsBackButton, QPushButton#DnsApplyButton, QPushButton#DnsAdapterPropertiesButton, QPushButton#PingBackButton,
QPushButton#PingSecondaryButton, QPushButton#LossBackButton, QPushButton#TcpBackButton,
QPushButton#TcpSecondaryButton, QPushButton#TlsBackButton,
QPushButton#TlsSecondaryButton, QPushButton#JitterBackButton,
QPushButton#JitterSecondaryButton, QPushButton#NetworkBoostButton,
QPushButton#NetworkBoostCancelButton, QPushButton#LossAutoCheckButton {
    color: #25313B;
    background-color: #FFFFFF;
    border-color: #C9D5D9;
}

QPushButton#DnsAdapterPropertiesButton:hover, QPushButton#NetworkBoostButton:hover,
QPushButton#NetworkBoostCancelButton:hover, QPushButton#LossAutoCheckButton:hover {
    color: #25313B;
    background-color: #EAF8F3;
    border-color: #00B982;
}

QPushButton#DnsInfoChip {
    color: #365061;
    background-color: #FFFFFF;
    border-color: #C9D5D9;
}

QPushButton#DnsInfoChip:hover {
    color: #17212B;
    background-color: #EAF8F3;
    border-color: #00B982;
}

QPushButton#DnsInfoChip:disabled {
    color: #80919B;
    background-color: #EEF2F3;
    border-color: #D9E2E5;
}

QLabel#NetworkBoostDialogStatus {
    color: #50616D;
    background-color: #F4F7F8;
    border-color: #D9E2E5;
}
QCheckBox#NetworkBoostCandidate {
    color: #25313B;
    background-color: #FFFFFF;
    border-color: #C9D5D9;
}
QCheckBox#NetworkBoostCandidate:hover { background-color: #EAF8F3; }
QCheckBox#NetworkBoostCandidate:disabled { color: #667784; }
QLabel#LatencyTooltip {
    color: #17212B;
    background-color: #FFFFFF;
    border-color: #C9D5D9;
}

QLabel#QuickFixTitle {
    color: #25313B;
}

QLabel#QuickFixStatus {
    color: #667784;
}

QPushButton#QuickFixButton {
    color: #25313B;
    background-color: #FFFFFF;
    border-color: #C9D5D9;
}

QPushButton#QuickFixButton:hover {
    background-color: #EAF8F3;
    border-color: #00B982;
}

QPushButton#QuickFixPrimary {
    color: #07352A;
    background-color: #00E5A3;
    border-color: #00B982;
}

QComboBox QAbstractItemView, QFrame#EmbeddedDropdown,
QListWidget#EmbeddedDropdownList {
    color: #25313B;
    background-color: #FFFFFF;
}

QComboBox:hover, QComboBox:focus, QLineEdit:focus, QSpinBox:focus,
QToolButton:hover, QPushButton#QuickActionButton:hover,
QCheckBox#UdpAnomalyFilter:hover {
    border-color: #00B982;
}

QRadioButton#ModeToggle:checked, QPushButton#PresetButton:checked {
    color: #07352A;
    background-color: #00E5A3;
    border-color: #00B982;
}

QTabBar::tab {
    color: #667784;
    background-color: #F4F7F8;
}

QTabBar::tab:selected, QTabBar::tab:hover {
    color: #17212B;
    background-color: #FFFFFF;
}

QTabWidget::pane {
    background-color: #FFFFFF;
    border-color: #D9E2E5;
}

QTableWidget, QPlainTextEdit {
    gridline-color: #E4ECEE;
    alternate-background-color: #F7FAFA;
    selection-background-color: #D8F6EC;
}

QTableWidget#DnsBenchmarkTable, QTableWidget#PingMatrixTable, QTableWidget#PingMtuTable,
QTableWidget#LossStressTable, QTableWidget#LossHopsTable, QTableWidget#TcpPortsTable,
QTableWidget#TcpSocketsTable, QTableWidget#TlsHandshakeTable, QTableWidget#TlsCertificateTable,
QTableWidget#JitterEventsTable {
    alternate-background-color: #F7FAFA;
    selection-background-color: #D8F6EC;
}

QTableWidget {
    color: #25313B;
}

QTableWidget::item {
    border-bottom-color: #E4ECEE;
}

QTableWidget::item:hover {
    background-color: #EAF8F3;
}

QHeaderView::section {
    color: #50616D;
    background-color: #EDF3F4;
    border-right-color: #D9E2E5;
    border-bottom-color: #D9E2E5;
}

QHeaderView::section:hover {
    color: #17212B;
    background-color: #E2F4ED;
}

QPlainTextEdit#PingSpikeLog {
    color: #35434F;
    background-color: #F8FBFB;
    border-color: #C9D5D9;
}

QPlainTextEdit#LossEventsLog {
    color: #35434F;
    background-color: #F8FBFB;
    border-color: #C9D5D9;
}

QScrollBar::handle:vertical {
    background: #B9C9CD;
}

QLabel#LiteCause, QLabel#LiteDetail, QLabel#LiteDetailCard {
    color: #25313B;
    background-color: #FFFFFF;
    border-color: #D9E2E5;
}

QProgressBar#QualityProgress, QToolButton#MetricHelpButton {
    background-color: #E8F0F0;
    border-color: #D9E2E5;
}

QFrame#BufferbloatPhaseCard, QFrame#BufferbloatGrade {
    background-color: #FFFFFF;
    border-color: #D9E2E5;
}

QLabel#BufferbloatValue, QLabel#BufferbloatGradeValue {
    color: #008A68;
}

QProgressBar#BufferbloatProgress {
    background-color: #E8F0F0;
}

QProgressBar#BufferbloatProgress::chunk {
    background-color: #00A77B;
}

QToolTip {
    color: #17212B;
    background-color: #FFFFFF;
    border-color: #C9D5D9;
}

QFrame#SessionCapsule {
    background-color: #FFFFFF;
    border-color: #C9D5D9;
}

QToolButton#SessionTimerButton,
QToolButton#SessionResetButton,
QToolButton#SessionLogButton {
    color: #50616D;
    background: transparent;
    border: 0;
}

QToolButton#SessionTimerButton {
    color: #17212B;
}

QToolButton#SessionTimerButton[paused="true"] {
    color: #667784;
}

QToolButton#SessionTimerButton:hover,
QToolButton#SessionResetButton:hover,
QToolButton#SessionLogButton:hover {
    color: #008E65;
    background-color: #EAF8F3;
}

QToolButton#SessionLogButton {
    border-left: 1px solid #D9E2E5;
}

QToolButton#SessionLogButton[anomalyState="good"] { color: #008E65; }
QToolButton#SessionLogButton[anomalyState="info"] { color: #1877B9; }
QToolButton#SessionLogButton[anomalyState="warning"] { color: #9A6500; }
QToolButton#SessionLogButton[anomalyState="error"] { color: #C53B49; }

QDialog#GameAutoCheckDialog {
    background-color: #F4F7F8;
}

QFrame#GameAutoCheckCard {
    background-color: #FFFFFF;
    border-color: #D9E2E5;
}

QLabel#GameAutoCheckTitle {
    color: #25313B;
}

QLabel#GameAutoCheckVersion {
    color: #667784;
}

QLabel#GameAutoCheckValue {
    color: #008E65;
}

QLabel#GameAutoCheckStatus {
    color: #667784;
}

QLabel#GameAutoCheckStatus[alertState="good"] { color: #008E65; background-color: #EAF8F3; }
QLabel#GameAutoCheckStatus[alertState="warning"] { color: #9A6500; background-color: #FFF5D8; }
QLabel#GameAutoCheckStatus[alertState="error"] { color: #C53B49; background-color: #FDECEE; }

QTableWidget#GameAutoCheckHistoryTable {
    background-color: #FFFFFF;
    border-color: #D9E2E5;
    alternate-background-color: #F7FAFA;
}

QMenu#SessionAnomalyMenu {
    background-color: #FFFFFF;
    border-color: #C9D5D9;
}

QFrame#SessionAnomalyMenuContent {
    background-color: #FFFFFF;
}

QLabel#SessionAnomalyMenuTitle {
    color: #667784;
}

QLabel#SessionAnomalyItem {
    color: #25313B;
    background-color: #F7FAFA;
    border-color: #D9E2E5;
}

QLabel#SessionAnomalyItem[anomalyState="warning"] { border-left-color: #B57800; }
QLabel#SessionAnomalyItem[anomalyState="error"] { border-left-color: #C53B49; }

QLabel#SessionAnomalyEmptyState {
    color: #667784;
}

QPushButton#SessionAnomalyOpenLogButton:hover {
    background-color: #55D6AE;
    border-color: #55D6AE;
}
"""

