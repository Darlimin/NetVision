import socket
from unittest.mock import patch

from netvision.core import tcp_diagnostics


class Connection:
    def __init__(self, pid: int, laddr: tuple[str, int], raddr: tuple[str, int], status: str) -> None:
        self.pid = pid
        self.laddr = laddr
        self.raddr = raddr
        self.status = status


def test_scans_tracked_tcp_socket_states() -> None:
    with patch.object(tcp_diagnostics.psutil, "net_connections") as connections_mock, patch.object(
        tcp_diagnostics.psutil, "Process"
    ) as process_mock:
        process_mock.return_value.name.return_value = "game.exe"
        connections_mock.return_value = [
            Connection(10, ("192.168.1.20", 50000), ("203.0.113.10", 443), "ESTABLISHED"),
            Connection(10, ("192.168.1.20", 50001), ("203.0.113.11", 80), "TIME_WAIT"),
            Connection(10, ("192.168.1.20", 50002), ("203.0.113.12", 80), "LISTEN"),
        ]

        records = tcp_diagnostics.scan_tcp_sockets()

    assert len(records) == 2
    assert records[0].process_name == "game.exe"
    assert records[0].remote_endpoint.endswith(":443")


def test_connect_probe_classifies_open_refused_and_timeout() -> None:
    class ConnectionContext:
        def __enter__(self) -> "ConnectionContext":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    with patch.object(tcp_diagnostics.socket, "create_connection", return_value=ConnectionContext()):
        opened = tcp_diagnostics.probe_tcp_connect("example.test", 443)
    with patch.object(tcp_diagnostics.socket, "create_connection", side_effect=ConnectionRefusedError()):
        refused = tcp_diagnostics.probe_tcp_connect("example.test", 80)
    with patch.object(tcp_diagnostics.socket, "create_connection", side_effect=socket.timeout()):
        timed_out = tcp_diagnostics.probe_tcp_connect("example.test", 3389)

    assert opened.is_open
    assert refused.status == "Закрыт"
    assert timed_out.status == "Фильтруется / timeout"


def test_port_probe_preserves_requested_order() -> None:
    with patch.object(
        tcp_diagnostics,
        "probe_tcp_connect",
        side_effect=lambda host, port, _timeout: tcp_diagnostics.TcpConnectMeasurement(host, port, 4.0, "Открыт"),
    ):
        results = tcp_diagnostics.probe_common_ports("example.test", (443, 80, 443))

    assert [result.port for result in results] == [443, 80]
