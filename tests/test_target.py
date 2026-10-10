import unittest

from netvision.core.target import parse_target


class ParseTargetTests(unittest.TestCase):
    def test_https_url_uses_https_port(self) -> None:
        target = parse_target("https://Example.COM/path")
        self.assertEqual(target.host, "example.com")
        self.assertEqual(target.port, 443)
        self.assertTrue(target.uses_tls)

    def test_explicit_port_overrides_url(self) -> None:
        target = parse_target("https://example.com:9443", 8443)
        self.assertEqual(target.port, 8443)

    def test_ipv6_address_is_supported(self) -> None:
        target = parse_target("[2001:db8::1]:443")
        self.assertEqual(target.host, "2001:db8::1")
        self.assertEqual(target.port, 443)

    def test_empty_target_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_target("  ")


if __name__ == "__main__":
    unittest.main()

