"""Offline regression tests for the legacy TransIP integration."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import pyDANETLSA as dane

ROOT = Path(__file__).resolve().parents[1]


class CompatibilityTests(unittest.TestCase):
    def test_legacy_and_current_certificate_results(self):
        for filetype in ('PEM', 'DER'):
            with self.subTest(filetype=filetype):
                cert = str(ROOT / 'testcert' / ('dummy.' + filetype.lower()))
                protocol = getattr(dane.DANETLSAprotocols, 'DANETLSA_' + filetype)
                current = dane.DANETLSA(fqdn='mail.example.org', port=25,
                                       app_protocol=protocol, certfile=cert)
                legacy = dane.danetlsa(fqdn='mail.example.org', port=25,
                                      probe_protocol=protocol, certfile=cert)
                current.connect()
                legacy.engage()
                self.assertEqual(current.tlsa_rdata_3_1_1(), legacy.tlsa_rdata_3_1_1())
                self.assertEqual(legacy.tlsa_rr_name_host(), '_25._tcp.mail')
                self.assertRegex(legacy.tlsa_rdata_3_1_1(), r'^3 1 1 [0-9a-f]{64}$')

    def test_legacy_protocol_and_transport(self):
        obj = dane.danetlsa(fqdn='mail.example.org', port=443,
                           protocol=dane.DANETLSA_TLS, tlsa_protocol='udp')
        self.assertEqual(obj.app_protocol, dane.DANETLSAprotocols.DANETLSA_TLS)
        self.assertEqual(obj.tlsa_rr_name_host(), '_443._udp.mail')

    def test_transip_integration_without_network(self):
        wrapper = ROOT.parent / 'transip-cmd' / 'transip-cmd.py'
        if not wrapper.exists():
            self.skipTest('Sibling transip-cmd checkout is not present')
        spec = importlib.util.spec_from_file_location('transip_cmd', wrapper)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        from argparse import Namespace
        args = Namespace(protocol='pem', fqdn='mail.example.org', port=25,
                         domain='example.org', tcpudp='tcp',
                         certfile=str(ROOT / 'testcert/dummy.pem'))
        domain = Mock()
        domain.dns.list.return_value = []
        with patch.object(dane.DANETLSA, "tlsa_target", return_value=("_25._tcp.mail.example.org.", ["_25._tcp.mail.example.org."])), patch.object(dane.dnstools, 'dns_query', side_effect=AssertionError('No network')):
            module.update_danetlsa(domain, args)
        record = domain.dns.create.call_args.args[0]
        self.assertEqual(record['name'], '_25._tcp.mail')
        self.assertEqual(record['type'], 'TLSA')
        self.assertRegex(record['content'], r'^3 1 1 [0-9a-f]{64}$')


if __name__ == '__main__':
    unittest.main()
