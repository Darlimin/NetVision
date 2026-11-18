"""Header panel for the dashboard."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMenu,
    QPushButton,
    QRadioButton,
    QSizePolicy,
    QStyle,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from netvision.ui.utils import keep_wheel_scroll_local
from netvision.ui.widgets import apply_panel_shadow
from netvision.version import display_version


class HeaderPanel(QFrame):
    def __init__(self, controller) -> None:
        super().__init__()
        header = self
        header.setObjectName("Header")
        apply_panel_shadow(header)
        layout = QHBoxLayout(header)
        # Keep the identity block flush with the header's left content edge.
        layout.setContentsMargins(0, 12, 18, 12)
        layout.setSpacing(6)

        self.header_brand = QWidget()
        self.header_brand.setObjectName("HeaderBrand")
        self.header_brand.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        self.header_brand.setMinimumWidth(190)
        brand_box = QVBoxLayout(self.header_brand)
        brand_box.setContentsMargins(0, 0, 0, 0)
        brand_box.setSpacing(0)
        brand = QLabel("NETVISION")
        brand.setObjectName("Brand")
        self.brand_caption = QLabel(f"NETWORK DIAGNOSTICS / WINDOWS · {display_version()}")
        self.brand_caption.setObjectName("BrandCaption")
        brand.setMargin(0)
        self.brand_caption.setMargin(0)
        brand_box.addWidget(brand)
        brand_box.addWidget(self.brand_caption)

        self.status_badge = QLabel()
        self.status_badge.setObjectName("HealthIndicator")
        self.status_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        # The exact width is updated from the active health text. Keep the
        # badge compact instead of allowing it to absorb header free space.
        self.status_badge.setMinimumWidth(250)
        self.status_badge.setMaximumWidth(340)
        self.status_badge.setMinimumHeight(38)
        self.status_badge.setSizePolicy(
            QSizePolicy.Policy.Fixed,
            QSizePolicy.Policy.Fixed,
        )
        self.status_badge.setAccessibleName("Индикатор здоровья сети")

        self.header_identity = QWidget()
        self.header_identity.setObjectName("HeaderIdentity")
        self.header_identity.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        identity_layout = QHBoxLayout(self.header_identity)
        identity_layout.setContentsMargins(0, 0, 0, 0)
        identity_layout.setSpacing(14)
        identity_layout.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        identity_layout.addWidget(self.header_brand)
        identity_layout.addWidget(self.status_badge)

        self.session_capsule = QFrame()
        self.session_capsule.setObjectName("SessionCapsule")
        self.session_capsule.setMinimumWidth(182)
        self.session_capsule.setMaximumWidth(520)
        self.session_capsule.setMinimumHeight(38)
        self.session_capsule.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Fixed,
        )
        session_layout = QHBoxLayout(self.session_capsule)
        session_layout.setContentsMargins(5, 3, 5, 3)
        session_layout.setSpacing(2)

        self.session_timer_button = QToolButton()
        self.session_timer_button.setObjectName("SessionTimerButton")
        self.session_timer_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.session_timer_button.clicked.connect(controller._toggle_session_timer)

        self.session_reset_button = QToolButton()
        self.session_reset_button.setObjectName("SessionResetButton")
        self.session_reset_button.setText("↺")
        self.session_reset_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.session_reset_button.clicked.connect(controller._reset_session_timer)

        self.session_log_button = QToolButton()
        self.session_log_button.setObjectName("SessionLogButton")
        self.session_log_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.session_log_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        self.session_log_button.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Fixed,
        )
        self.session_log_button.clicked.connect(controller._toggle_header_anomaly_menu)
        controller._header_anomaly_menu = QMenu(self)
        controller._header_anomaly_menu.setObjectName("SessionAnomalyMenu")
        controller._header_anomaly_menu.setSeparatorsCollapsible(False)
        controller._header_anomaly_menu.aboutToShow.connect(
            controller.alarms_controller._populate_header_anomaly_menu
        )

        session_layout.addWidget(self.session_timer_button)
        session_layout.addWidget(self.session_reset_button)
        session_layout.addWidget(self.session_log_button, 1)

        self.mode_label = QLabel("РЕЖИМ")
        self.mode_label.setObjectName("ModeLabel")
        self.expert_mode_button = QRadioButton("Эксперт")
        self.expert_mode_button.setObjectName("ModeToggle")
        self.lite_mode_button = QRadioButton("Простой режим")
        self.lite_mode_button.setObjectName("ModeToggle")
        self.mode_button_group = QButtonGroup(self)
        self.mode_button_group.setExclusive(True)
        self.mode_button_group.addButton(self.expert_mode_button)
        self.mode_button_group.addButton(self.lite_mode_button)
        self.expert_mode_button.setChecked(True)
        self.expert_mode_button.toggled.connect(
            lambda checked: checked and controller._set_interface_mode("expert")
        )
        self.lite_mode_button.toggled.connect(
            lambda checked: checked and controller._set_interface_mode("lite")
        )

        self.export_button = QToolButton()
        self.export_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton)
        )
        self.export_button.setToolTip("Экспортировать диагностический отчёт в JSON")
        self.export_button.setAccessibleName("Экспортировать отчёт")
        self.export_button.setFixedSize(36, 36)
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(controller._export_report)

        self.support_bundle_button = QToolButton()
        self.support_bundle_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView)
        )
        self.support_bundle_button.setToolTip("Экспортировать пакет для техподдержки")
        self.support_bundle_button.setAccessibleName("Экспортировать пакет для техподдержки")
        self.support_bundle_button.setFixedSize(36, 36)
        self.support_bundle_button.setEnabled(False)
        self.support_bundle_button.clicked.connect(
            controller.diagnostics_coordinator._export_support_bundle
        )

        self.connection_capture_button = QPushButton("⌕  Выбрать соединение")
        self.connection_capture_button.setObjectName("ProcessCaptureButton")
        self.connection_capture_button.setToolTip(controller._tr("Выбрать соединение"))
        self.connection_capture_button.setAccessibleName(controller._tr("Выбрать соединение"))
        self.connection_capture_button.setMinimumWidth(158)
        self.connection_capture_button.clicked.connect(controller._open_connection_capture_dialog)

        self.manual_process_button = QPushButton("Сменить процесс")
        self.manual_process_button.setObjectName("ManualProcessButton")
        self.manual_process_button.setToolTip(controller._tr("Выбрать процесс вручную"))
        self.manual_process_button.setAccessibleName(controller._tr("Выбрать процесс вручную"))
        self.manual_process_button.setMinimumWidth(144)
        self.manual_process_button.clicked.connect(controller._open_manual_process_dialog)

        self.header_settings = QWidget()
        self.header_settings.setObjectName("HeaderSettings")
        self.header_settings.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        settings_layout = QHBoxLayout(self.header_settings)
        settings_layout.setContentsMargins(0, 0, 0, 0)
        settings_layout.setSpacing(5)

        self.language_label = QLabel("ЯЗЫК")
        self.language_label.setObjectName("ModeLabel")
        self.language_combo = QComboBox()
        self.language_combo.setObjectName("LanguageSelector")
        self.language_combo.setToolTip("Выбрать язык интерфейса / Choose interface language")
        self.language_combo.addItem("RU", "ru")
        self.language_combo.addItem("EN", "en")
        self.language_combo.setCurrentIndex(0)
        self.language_combo.setMinimumWidth(58)
        self.language_combo.setMaximumWidth(66)
        self.language_combo.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.language_combo.setFocusPolicy(Qt.FocusPolicy.WheelFocus)
        keep_wheel_scroll_local(self.language_combo.view())
        self.language_combo.currentIndexChanged.connect(controller._on_language_changed)

        self.theme_button = QToolButton()
        self.theme_button.setObjectName("ThemeToggle")
        self.theme_button.setText("☾")
        self.theme_button.setToolTip("Переключить на светлую тему")
        self.theme_button.setAccessibleName("Переключатель тёмной и светлой темы")
        self.theme_button.setFixedSize(36, 36)
        self.theme_button.clicked.connect(controller._toggle_theme)

        # Keep the edge controls anchored on wide screens. The two stretches
        # reserve the free width around the central session capsule instead of
        # spreading it between every header control.
        layout.addWidget(
            self.header_identity,
            0,
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
        )
        layout.addStretch(1)
        layout.addWidget(self.session_capsule, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addStretch(1)
        settings_layout.addWidget(self.language_label)
        settings_layout.addWidget(self.language_combo)
        settings_layout.addWidget(self.theme_button)

        self.header_mode_controls = QWidget()
        self.header_mode_controls.setObjectName("HeaderModeControls")
        self.header_mode_controls.setSizePolicy(
            QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed
        )
        mode_layout = QHBoxLayout(self.header_mode_controls)
        mode_layout.setContentsMargins(0, 0, 0, 0)
        mode_layout.setSpacing(5)
        mode_layout.addWidget(self.mode_label)
        mode_layout.addWidget(self.expert_mode_button)
        mode_layout.addWidget(self.lite_mode_button)

        layout.addWidget(self.header_mode_controls, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self.export_button, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self.support_bundle_button, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(
            self.header_settings,
            0,
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
        )
