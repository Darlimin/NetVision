"""Shared network-quality thresholds used by diagnostics and UI helpers."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Thresholds:
    jitter_spike_ms: float = 15.0
    jitter_critical_ms: float = 25.0
    jitter_bad_ms: float = 30.0
    jitter_clear_ms: float = 10.0
    rtt_high_ms: float = 100.0
    rtt_peak_ms: float = 150.0
    rtt_normal_ms: float = 80.0
    dns_good_ms: float = 30.0
    dns_ok_ms: float = 80.0
    episode_quiet_samples: int = 3
    mtu_search_min: int = 576
    mtu_search_max: int = 1500
    mtu_probe_timeout_ms: int = 900
    mtu_probe_retries: int = 2
    mtu_probe_budget_s: float = 30.0
    mtu_apply_min_delta: int = 8
    action_confirm_timeout_s: float = 20.0
    bufferbloat_load_s: float = 8.0
    bufferbloat_baseline_s: float = 3.0
    bufferbloat_streams: int = 4
    bufferbloat_max_bytes: int = 256 * 1024 * 1024
    bufferbloat_sample_interval_s: float = 0.25
    bufferbloat_grade_steps_ms: tuple[int, ...] = (5, 15, 30, 60, 100)
    bufferbloat_local_delta_ms: float = 15.0
    mtr_interval_s: float = 1.0
    mtr_max_hops: int = 20
    mtr_probe_timeout_ms: int = 700
    mtr_window_cycles: int = 100
    mtr_loss_warn_pct: float = 5.0
    mtr_loss_clear_pct: float = 1.0
    mtr_confirm_cycles: int = 5
    stun_timeout_s: float = 1.5
    stun_retries: int = 2
    cgnat_hop_limit: int = 4
    wifi_poll_interval_s: float = 5.0
    wifi_signal_warn_pct: int = 60
    wifi_signal_crit_pct: int = 40
    wifi_signal_hysteresis_pct: int = 5
    wifi_gateway_rtt_warn_ms: float = 15.0
    correlation_window_s: float = 10.0
    alarm_cooldown_s: float = 60.0
    export_max_events: int = 5000


DEFAULT_THRESHOLDS = Thresholds()
