"""Qt worker adapters for core network operations being migrated."""

from concurrent.futures import CancelledError
from collections.abc import Callable
from threading import Event

from PySide6.QtCore import QObject, Signal, Slot
from PySide6.QtWidgets import QPushButton

from netvision.core.diagnostics import DiagnosticService
from netvision.core.geohide import fetch_geohide_dns
from netvision.core.process_inspector import ProcessScanResult, scan_process, scan_processes
from netvision.core.system_actions import SystemActionResult
from netvision.core.traceroute import run_visual_traceroute
from netvision.models import Target
from netvision.models import HopResult, SystemSnapshot
from netvision.core.process_inspector import ProcessListResult, list_running_processes
from netvision.core.network_boost import (
    BackgroundTrafficCandidate,
    NetworkBoostScanResult,
    ProcessTerminationResult,
    scan_background_traffic_candidates,
    terminate_background_candidates,
)
from netvision.core.internet_quality import (
    PublicIpAddresses,
    fetch_public_ip_addresses,
    fetch_public_network_info,
    run_internet_quality_check,
)
from netvision.core.nat_diagnostics import probe_nat
from netvision.core.thresholds import Thresholds, DEFAULT_THRESHOLDS
from netvision.core.bufferbloat import run_bufferbloat_test
from netvision.core.game_monitor import GameLaunchMonitor
from netvision.core.dns_benchmark import DnsResolverProfile, benchmark_resolvers
from netvision.core.system import (
    active_network_identity,
    active_network_identity_fast,
    collect_dns_configuration,
)
from netvision.core.ping_benchmark import (
    RegionalPingTarget,
    benchmark_regional_targets,
    run_mtu_stress_test,
)
from netvision.core.mtu_optimizer import run_mtu_optimizer, probe_path_mtu
from netvision.core.packet_loss import (
    run_hop_loss_breakdown,
    run_icmp_stress_test,
    run_udp_stress_test,
)
from netvision.core.udp_stress import run_udp_packet_loss_stress
from netvision.core.tcp_diagnostics import scan_tcp_sockets, probe_tcp_connect, probe_common_ports
from netvision.core.tls_diagnostics import audit_tls_endpoint


class CancellableWorker(QObject):
    finished = Signal()

    def __init__(self) -> None:
        super().__init__()
        self._cancel_event = Event()

    def stop(self) -> None:
        self._cancel_event.set()

    def _check_cancelled(self) -> None:
        if self._cancel_event.is_set():
            raise CancelledError()


class GeoHideWorker(CancellableWorker):
    completed = Signal(object)
    failed = Signal(str)

    @Slot()
    def run(self) -> None:
        try:
            self._check_cancelled()
            result = fetch_geohide_dns()
            self._check_cancelled()
            self.completed.emit(result)
        except CancelledError:
            pass
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.finished.emit()


class ProcessScanWorker(QObject):
    completed = Signal(object)

    @Slot()
    def run(self) -> None:
        try:
            result = scan_processes()
        except Exception as exc:
            result = ProcessScanResult((), f"Не удалось просканировать процессы: {exc}")
        self.completed.emit(result)


class DiagnosticWorker(QObject):
    progress = Signal(str, str)
    completed = Signal(object)
    failed = Signal(object)

    def __init__(self, target: Target) -> None:
        super().__init__()
        self._target = target

    @Slot()
    def run(self) -> None:
        try:
            report = DiagnosticService().run(self._target, self.progress.emit)
        except Exception as exc:  # Last-resort boundary for the worker thread.
            self.failed.emit(exc)
            return
        self.completed.emit(report)


class SystemActionWorker(QObject):
    completed = Signal(str, object, object)

    def __init__(
        self,
        label: str,
        button: QPushButton,
        action: Callable[[], SystemActionResult],
    ) -> None:
        super().__init__()
        self._label = label
        self._button = button
        self._action = action

    @Slot()
    def run(self) -> None:
        try:
            result = self._action()
        except Exception as exc:  # Keep system actions from crossing into the GUI thread.
            result = SystemActionResult(False, f"Системное действие завершилось ошибкой: {exc}")
        self.completed.emit(self._label, self._button, result)


class ProcessSocketsWorker(QObject):
    """Read sockets only for the already selected process."""

    completed = Signal(object)

    def __init__(self, pid: int) -> None:
        super().__init__()
        self._pid = pid

    @Slot()
    def run(self) -> None:
        try:
            result = scan_process(self._pid)
        except Exception as exc:  # Keep per-process inspection failures off the GUI thread.
            result = ProcessScanResult((), f"Не удалось прочитать сокеты процесса: {exc}")
        self.completed.emit(result)


class TracerouteWorker(QObject):
    """Stream traceroute hops from a worker thread to the visual route table."""

    hop_found = Signal(object)
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, host: str) -> None:
        super().__init__()
        self._host = host

    @Slot()
    def run(self) -> None:
        try:
            hops = run_visual_traceroute(self._host, on_hop=self.hop_found.emit)
        except Exception as exc:
            self.failed.emit(f"Трассировка завершилась ошибкой: {exc}")
            return
        self.completed.emit(hops)


class RunningProcessListWorker(QObject):
    completed = Signal(object)

    @Slot()
    def run(self) -> None:
        try:
            result = list_running_processes()
        except Exception as exc:  # Keep process enumeration failures inside the worker.
            result = ProcessListResult((), str(exc))
        self.completed.emit(result)


class NetworkBoostScanWorker(QObject):
    """Find safe, recognised background network consumers outside the GUI thread."""

    completed = Signal(object)

    @Slot()
    def run(self) -> None:
        try:
            result = scan_background_traffic_candidates()
        except Exception as exc:  # Keep a scanner failure out of the GUI thread.
            result = NetworkBoostScanResult((), f"Не удалось выполнить Network Boost: {exc}")
        self.completed.emit(result)


class NetworkBoostTerminateWorker(QObject):
    """Gracefully terminate only the candidates explicitly chosen in the dialog."""

    completed = Signal(object)

    def __init__(self, candidates: tuple[BackgroundTrafficCandidate, ...]) -> None:
        super().__init__()
        self._candidates = candidates

    @Slot()
    def run(self) -> None:
        try:
            results = terminate_background_candidates(self._candidates)
        except Exception as exc:  # Last-resort boundary for psutil operations.
            results = tuple(
                ProcessTerminationResult(
                    candidate.pid, candidate.name, False, f"Ошибка завершения: {exc}"
                )
                for candidate in self._candidates
            )
        self.completed.emit(results)


class InternetQualityWorker(QObject):
    progress = Signal(str)
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, system_snapshot: SystemSnapshot | None = None) -> None:
        super().__init__()
        self._system_snapshot = system_snapshot

    @Slot()
    def run(self) -> None:
        try:
            report = run_internet_quality_check(
                self._system_snapshot,
                self.progress.emit,
            )
        except Exception as exc:  # Keep external services from crossing into the GUI thread.
            self.failed.emit(f"Проверка качества завершилась ошибкой: {exc}")
            return
        self.completed.emit(report)


class NatProbeWorker(QObject):
    """Run the UDP-only STUN check outside the Qt GUI thread."""

    completed = Signal(object)
    failed = Signal(str)

    def __init__(
        self,
        external_ip: str | None,
        hops: tuple[HopResult, ...],
        thresholds: Thresholds,
    ) -> None:
        super().__init__()
        self._external_ip = external_ip
        self._hops = hops
        self._thresholds = thresholds

    @Slot()
    def run(self) -> None:
        try:
            report = probe_nat(
                timeout_s=self._thresholds.stun_timeout_s,
                retries=self._thresholds.stun_retries,
                external_ip=self._external_ip,
                hops=self._hops,
                cgnat_hop_limit=self._thresholds.cgnat_hop_limit,
            )
        except Exception as exc:
            self.failed.emit(f"Ошибка STUN-проверки: {exc}")
            return
        self.completed.emit(report)


class BufferbloatWorker(QObject):
    progress = Signal(str)
    completed = Signal(object)
    failed = Signal(str)

    def __init__(
        self,
        target: str | None,
        gateway: str | None,
        th: Thresholds = DEFAULT_THRESHOLDS,
    ) -> None:
        super().__init__()
        self._target = target
        self._gateway = gateway
        self._thresholds = th
        self._stop_event = Event()

    def stop(self) -> None:
        self._stop_event.set()

    @Slot()
    def run(self) -> None:
        try:
            self.completed.emit(
                run_bufferbloat_test(
                    self.progress.emit,
                    target=self._target,
                    gateway=self._gateway,
                    stop_event=self._stop_event,
                    thresholds=self._thresholds,
                )
            )
        except Exception as exc:
            self.failed.emit(f"Тест bufferbloat завершился ошибкой: {exc}")


class GameLaunchMonitorWorker(QObject):
    event = Signal(object)
    finished = Signal()

    def __init__(
        self,
        process_names: tuple[str, ...] = (),
        target: tuple[str, int] = ("1.1.1.1", 53),
    ) -> None:
        super().__init__()
        self._stop_event = Event()
        self._process_names = process_names
        self._target = target

    def stop(self) -> None:
        self._stop_event.set()

    @Slot()
    def run(self) -> None:
        monitor = GameLaunchMonitor(self._process_names, self._target)
        try:
            while not self._stop_event.is_set():
                update = monitor.poll()
                if update is not None:
                    self.event.emit(update)
                self._stop_event.wait(5.0)
        finally:
            final_event = monitor.close()
            if final_event is not None:
                self.event.emit(final_event)
            self.finished.emit()


class _CancellableWorker(QObject):
    finished = Signal()

    def __init__(self) -> None:
        super().__init__()
        self._cancel_event = Event()

    def stop(self) -> None:
        self._cancel_event.set()

    def _check_cancelled(self) -> None:
        if self._cancel_event.is_set():
            raise CancelledError()


class DnsBenchmarkWorker(_CancellableWorker):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, profiles: tuple[DnsResolverProfile, ...]) -> None:
        super().__init__()
        self._profiles = profiles

    @Slot()
    def run(self) -> None:
        try:
            self._check_cancelled()
            result = benchmark_resolvers(self._profiles, cancel_event=self._cancel_event)
            self._check_cancelled()
            self.completed.emit(result)
        except CancelledError:
            pass
        except Exception as exc:
            self.failed.emit(f"DNS-бенчмарк завершился ошибкой: {exc}")
        finally:
            self.finished.emit()


class DnsConfigurationWorker(_CancellableWorker):
    completed = Signal(object, object, object, object)
    failed = Signal(str)

    @Slot()
    def run(self) -> None:
        try:
            self._check_cancelled()
            before = active_network_identity()
            configuration = collect_dns_configuration()
            self._check_cancelled()
            public_addresses = fetch_public_ip_addresses(cancel_event=self._cancel_event)
            network = fetch_public_network_info(timeout=3)
            if network.ipv4:
                public_addresses = PublicIpAddresses(
                    ipv4=network.ipv4, ipv6=public_addresses.ipv6, error=public_addresses.error
                )
            after = active_network_identity()
            self._check_cancelled()
            self.completed.emit(configuration, public_addresses, before, after)
        except CancelledError:
            pass
        except Exception as exc:
            self.failed.emit(f"Не удалось получить системные DNS: {exc}")
        finally:
            self.finished.emit()


class NetworkIdentityWorker(QObject):
    completed = Signal(object)
    finished = Signal()

    @Slot()
    def run(self) -> None:
        try:
            self.completed.emit(active_network_identity_fast())
        except (OSError, ValueError):
            self.completed.emit(None)
        finally:
            self.finished.emit()


class PingBenchmarkWorker(QObject):
    """Run regional latency and MTU checks outside the Qt GUI thread."""

    completed = Signal(object, object)
    failed = Signal(str)

    def __init__(
        self,
        mtu_host: str,
        *,
        include_matrix: bool,
        include_mtu: bool,
        regional_targets: tuple[RegionalPingTarget, ...] | None = None,
    ) -> None:
        super().__init__()
        self._mtu_host = mtu_host
        self._include_matrix = include_matrix
        self._include_mtu = include_mtu
        self._regional_targets = regional_targets

    @Slot()
    def run(self) -> None:
        try:
            regional_results = (
                benchmark_regional_targets(self._regional_targets)
                if self._include_matrix and self._regional_targets
                else benchmark_regional_targets() if self._include_matrix else ()
            )
            mtu_results = run_mtu_stress_test(self._mtu_host) if self._include_mtu else ()
        except Exception as exc:
            self.failed.emit(f"Анализ задержки завершился ошибкой: {exc}")
            return
        self.completed.emit(regional_results, mtu_results)


class MtuOptimizerWorker(_CancellableWorker):
    """Discover a non-fragmenting path MTU outside the GUI thread."""

    progress = Signal(str)
    completed = Signal(object)
    failed = Signal(str)

    def __init__(
        self,
        target_host: str,
        snapshot: SystemSnapshot | None = None,
        th: Thresholds = DEFAULT_THRESHOLDS,
    ) -> None:
        super().__init__()
        self._target_host = target_host
        self._snapshot = snapshot
        self._thresholds = th

    @Slot()
    def run(self) -> None:
        try:
            self._check_cancelled()
            result = run_mtu_optimizer(
                self._target_host,
                progress=self.progress.emit,
                snapshot=self._snapshot,
                th=self._thresholds,
                cancel_event=self._cancel_event,
            )
            self._check_cancelled()
            self.completed.emit(result)
        except CancelledError:
            pass
        except Exception as exc:
            self.failed.emit(f"MTU-оптимизатор завершился ошибкой: {exc}")
        finally:
            self.finished.emit()


class MtuControlProbeWorker(_CancellableWorker):
    """Check the active MTU trial without blocking the confirmation dialog."""

    completed = Signal(object)

    def __init__(self, target_ip: str, mtu: int, timeout_ms: int) -> None:
        super().__init__()
        self._target_ip = target_ip
        self._mtu = mtu
        self._timeout_ms = timeout_ms

    @Slot()
    def run(self) -> None:
        try:
            self._check_cancelled()
            result = probe_path_mtu(self._target_ip, self._mtu, self._timeout_ms)
            self._check_cancelled()
            self.completed.emit(result)
        except CancelledError:
            pass
        finally:
            self.finished.emit()


class PacketLossTestWorker(QObject):
    """Keep hop and controlled packet-burst checks off the Qt GUI thread."""

    completed = Signal(object, object, object)
    failed = Signal(str)

    def __init__(self, hops: tuple[HopResult, ...], host: str, port: int) -> None:
        super().__init__()
        self._hops = hops
        self._host = host
        self._port = port

    @Slot()
    def run(self) -> None:
        try:
            hop_results = run_hop_loss_breakdown(self._hops) if self._hops else ()
            icmp_result = run_icmp_stress_test(self._host)
            udp_result = run_udp_stress_test(self._host, self._port)
        except Exception as exc:
            self.failed.emit(f"Анализ потерь завершился ошибкой: {exc}")
            return
        self.completed.emit(hop_results, icmp_result, udp_result)


class UdpStressWorker(QObject):
    """Run the measured UDP request/response check away from the GUI thread."""

    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, host: str, port: int) -> None:
        super().__init__()
        self._host = host
        self._port = port

    @Slot()
    def run(self) -> None:
        try:
            report = run_udp_packet_loss_stress(self._host, self._port)
        except Exception as exc:
            self.failed.emit(f"UDP-стресс завершился ошибкой: {exc}")
            return
        self.completed.emit(report)


class TcpDiagnosticsWorker(_CancellableWorker):
    """Collect socket state and TCP connect checks outside the GUI thread."""

    completed = Signal(object, object, object)
    failed = Signal(str)

    def __init__(self, host: str, port: int, ports: tuple[int, ...]) -> None:
        super().__init__()
        self._host = host
        self._port = port
        self._ports = ports

    @Slot()
    def run(self) -> None:
        try:
            self._check_cancelled()
            sockets = scan_tcp_sockets()
            self._check_cancelled()
            primary = probe_tcp_connect(self._host, self._port)
            self._check_cancelled()
            ports = probe_common_ports(self._host, self._ports, cancel_event=self._cancel_event)
            self._check_cancelled()
        except CancelledError:
            return
        except Exception as exc:
            self.failed.emit(f"TCP-анализ завершился ошибкой: {exc}")
            return
        else:
            self.completed.emit(sockets, primary, ports)
        finally:
            self.finished.emit()


class TlsAuditWorker(QObject):
    """Run a TLS audit outside the Qt GUI thread."""

    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, host: str, port: int) -> None:
        super().__init__()
        self._host = host
        self._port = port

    @Slot()
    def run(self) -> None:
        try:
            self.completed.emit(audit_tls_endpoint(self._host, self._port))
        except Exception as exc:
            self.failed.emit(f"TLS-аудит завершился ошибкой: {exc}")
