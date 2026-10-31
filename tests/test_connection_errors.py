import socket
import ssl
import unittest
from unittest.mock import patch
from pyDANETLSA import DANETLSA, DANETLSAConnectionError


class ConnectionErrors(unittest.TestCase):
    def test_expected_errors_have_context_and_original_cause(self):
        cases = [
            (TimeoutError(), "timed out"),
            (ConnectionRefusedError(), "connection refused"),
            (socket.gaierror("not found"), "hostname lookup failed"),
            (ssl.SSLError("handshake failure"), "TLS handshake failed"),
            (OSError(101, "Network is unreachable"), "Network is unreachable"),
        ]
        for error, message in cases:
            with self.subTest(error=type(error).__name__):
                probe = DANETLSA(fqdn="smtp.example.org", port=465)
                with patch("pyDANETLSA.ssl.get_server_certificate", side_effect=error):
                    with self.assertRaises(DANETLSAConnectionError) as result:
                        probe.connect()
                self.assertIn("smtp.example.org:465 (TLS)", str(result.exception))
                self.assertIn(message, str(result.exception))
                self.assertIs(result.exception.__cause__, error)

    def test_programming_errors_are_not_hidden(self):
        probe = DANETLSA(fqdn="smtp.example.org", port=465)
        with patch("pyDANETLSA.ssl.get_server_certificate", side_effect=TypeError("bug")):
            with self.assertRaises(TypeError):
                probe.connect()
