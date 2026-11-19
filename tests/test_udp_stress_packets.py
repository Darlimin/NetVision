import struct

from netvision.core.udp_stress import _dns_query, _stun_query


def test_dns_query_has_transaction_and_example_question():
    packet = _dns_query(0x1234)
    assert struct.unpack("!HHHHHH", packet[:12]) == (0x1234, 0x100, 1, 0, 0, 0)
    assert packet[12:] == b"\x07example\x03com\x00\x00\x01\x00\x01"


def test_stun_binding_request():
    transaction = bytes(range(12))
    packet = _stun_query(transaction)
    assert packet == b"\x00\x01\x00\x00\x21\x12\xa4\x42" + transaction
