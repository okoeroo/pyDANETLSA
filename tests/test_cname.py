import importlib.util
import unittest
from argparse import Namespace
from unittest.mock import Mock, patch
import dns.name
import dns.resolver
from pyDANETLSA import resolve_tlsa_owner, TLSAResolutionError


class CnameTests(unittest.TestCase):
    def test_chain_and_loop_and_failure(self):
        record = Mock(target=dns.name.from_text("real.example.org."))
        with patch("dns.resolver.Resolver") as resolver:
            resolver.return_value.resolve.side_effect = [[record], dns.resolver.NoAnswer()]
            target, chain = resolve_tlsa_owner("_25._tcp.mail.example.org.")
            self.assertEqual(target, "real.example.org.")
            self.assertEqual(len(chain), 2)
            resolver.return_value.resolve.side_effect = [[record], [record]]
            with self.assertRaises(TLSAResolutionError):
                resolve_tlsa_owner("_25._tcp.mail.example.org.")
            resolver.return_value.resolve.side_effect = dns.resolver.LifetimeTimeout()
            with self.assertRaises(TLSAResolutionError):
                resolve_tlsa_owner("_25._tcp.mail.example.org.")

    def test_updates_target_preserves_cname_and_other_tlsa(self):
        spec = importlib.util.spec_from_file_location("cmd", "/home/okoeroo/transip-cmd/transip-cmd.py")
        cmd = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cmd)
        args = Namespace(protocol="tls", fqdn="mail.example.org", port=465,
                         domain="example.org", tcpudp="tcp", certfile=None)
        domain = Mock()
        old = Mock(expire=300, type="TLSA", content="3 1 1 old")
        old.name = "real"
        other = Mock(expire=300, type="TLSA", content="2 1 1 keep")
        other.name = "real"
        domain.dns.list.return_value = [old, other]
        with patch.object(cmd, "DANETLSA") as factory:
            probe = factory.return_value
            probe.tlsa_target.return_value = ("real.example.org.", ["alias.example.org.", "real.example.org."])
            probe.tlsa_rdata_3_1_1.return_value = "3 1 1 new"
            cmd.update_danetlsa(domain, args)
            self.assertEqual(domain.dns.create.call_args.args[0]["name"], "real")
            domain.dns.delete.assert_called_once_with(dict(name="real", expire=300, type="TLSA", content="3 1 1 old"))
            domain.reset_mock()
            old.content = "3 1 1 new"
            cmd.update_danetlsa(domain, args)
            domain.dns.create.assert_not_called()
            domain.dns.delete.assert_not_called()
            probe.tlsa_target.return_value = ("external.other.org.", ["external.other.org."])
            with self.assertRaises(TLSAResolutionError):
                cmd.update_danetlsa(domain, args)
            domain.dns.create.assert_not_called()

    def test_failed_pin_never_mutates_dns(self):
        from pyDANETLSA import TLSAValidationError
        spec = importlib.util.spec_from_file_location("cmd", "/home/okoeroo/transip-cmd/transip-cmd.py")
        cmd = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cmd)
        args = Namespace(protocol="smtp", fqdn="mail.example.org", port=25,
                         domain="example.org", tcpudp="tcp", certfile=None,
                         tlsa_311="auto", tlsa_211="auto")
        for method in ("tlsa_rdata_3_1_1", "tlsa_rdata_2_1_1"):
            with self.subTest(method=method), patch.object(cmd, "DANETLSA") as factory:
                domain = Mock()
                getattr(factory.return_value, method).side_effect = TLSAValidationError("mismatch")
                with self.assertRaises(TLSAValidationError):
                    cmd.update_danetlsa(domain, args)
                domain.dns.create.assert_not_called()
                domain.dns.delete.assert_not_called()
