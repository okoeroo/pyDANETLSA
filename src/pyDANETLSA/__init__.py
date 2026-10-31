#!/usr/bin/env python3

import os
import ssl
import socket
import ftplib
import imaplib
import poplib
import smtplib
import OpenSSL.crypto as crypto
from enum import Enum

from .libs import funcs
from .libs import dnstools
from .libs.dnstools import TLSAResolutionError, resolve_tlsa_owner


class DANETLSAConnectionError(Exception):
    """Certificate probing failed; the original exception is available as __cause__."""


class DANETLSAprotocols(Enum):
    DANETLSA_IMAP = 10
    DANETLSA_POP3 = 20
    DANETLSA_SMTP = 30
    DANETLSA_TLS  = 40
    DANETLSA_PEM  = 50
    DANETLSA_DER  = 60
    DANETLSA_FTP  = 70


def DANETLS_protocol_to_str(protocol):
    if protocol not in DANETLSAprotocols:
        raise ValueError("Unknown protocol/method set")

    if   protocol == DANETLSAprotocols.DANETLSA_IMAP: return "IMAP"
    elif protocol == DANETLSAprotocols.DANETLSA_POP3: return "POP3"
    elif protocol == DANETLSAprotocols.DANETLSA_SMTP: return "SMTP"
    elif protocol == DANETLSAprotocols.DANETLSA_TLS : return "TLS"
    elif protocol == DANETLSAprotocols.DANETLSA_PEM : return "PEM"
    elif protocol == DANETLSAprotocols.DANETLSA_DER : return "DER"
    elif protocol == DANETLSAprotocols.DANETLSA_FTP : return "FTP"


def str_to_DANETLS_protocol(proto: str):
    if   proto.upper() == "IMAP": return DANETLSAprotocols.DANETLSA_IMAP
    elif proto.upper() == "POP3": return DANETLSAprotocols.DANETLSA_POP3
    elif proto.upper() == "SMTP": return DANETLSAprotocols.DANETLSA_SMTP
    elif proto.upper() == "TLS":  return DANETLSAprotocols.DANETLSA_TLS
    elif proto.upper() == "PEM":  return DANETLSAprotocols.DANETLSA_PEM
    elif proto.upper() == "DER":  return DANETLSAprotocols.DANETLSA_DER
    elif proto.upper() == "FTP":  return DANETLSAprotocols.DANETLSA_FTP
    else:
        raise ValueError("Unknown protocol provided")


def DANETLSA_get_supported_protocols():
    return [DANETLS_protocol_to_str(i) for i in DANETLSAprotocols]


class DANETLSA(object):

    """
    IMAP: StartTLS for IMAP
    POP3: StartTLS for POP3
    SMTP: StartTLS for SMTP
    TLS : Plain TLS protocol, any application protocol
    PEM : Input is a X.509 certificate in PEM format
    DER : Input is a X.509 certificate in DER format
    FTP : StartTLS for FTP
    """
    def __init__(self, fqdn=None, port=None, domain=None,
                       transport_proto='tcp', app_protocol=DANETLSAprotocols.DANETLSA_TLS,
                       certfile=None, timeout=10):
        if transport_proto.lower() not in ['tcp', 'udp', 'sctp']:
            raise ValueError("Unknown protocol/method set for TLSA output record.")

        if app_protocol not in DANETLSAprotocols:
            raise ValueError("Unknown protocol/method set for reading/probing.")

        if fqdn is None:
            raise ValueError("No fqdn provided")

        if port is None:
            raise ValueError("No port provided")

        # Fill class with values
        self.fqdn = fqdn
        self.port = port
        self.transport_proto = transport_proto.lower()
        self.app_protocol = app_protocol
        self.domain = domain
        self.certfile = certfile
        self.timeout = timeout # seconds

        # Normalization
        if self.fqdn[-1] == '.':
            self.fqdn = self.fqdn[:-1]

        if self.domain is None:
            # Chop last two domain elements off, zone with TLD
            self.host = ".".join(self.fqdn.split('.')[:-2])

            self.domain = ".".join([self.fqdn.split('.')[-2],
                                    self.fqdn.split('.')[-1]])
        else:
            # Normalize
            if self.domain[-1] == '.':
                self.domain = self.domain[:-1]

            self.host = ".".join(self.fqdn.split('.')[:-len(self.domain.split('.'))])

        # Check if the file exists
        if self.certfile is not None:
            if not os.path.exists(self.certfile):
                raise IOError("file '{}' does not exist.".format(self.certfile))
            if not os.path.isfile(self.certfile):
                raise IOError("file '{}' is not a file.".format(self.certfile))

    def tlsa_target(self):
        return resolve_tlsa_owner(self.tlsa_rr_name_fqdn())

    def dns_tlsa(self):
        # Parse and construct config for dnspython
        dns_config = dnstools.DnsPythonConfig(None)
        target, self.cname_chain = self.tlsa_target()
        status, answers = dnstools.dns_query(target,
                                    'TLSA',
                                    None,
                                    False)
        if status != dnstools.DNSERRORS.NOERROR:
            return None

        return sorted([str(rr) for rr in answers])

    def match_cert_with_tlsa_rr(self):
        dns_tlsa_list = self.dns_tlsa()
        x509_tlsa_3_1_1 = self.tlsa_rdata_3_1_1()

        if dns_tlsa_list is None:
            return False

        for rr in dns_tlsa_list:
            if x509_tlsa_3_1_1 == rr:
                return True
        else:
            return False


#    def stuff(self):
#        return funcs.returnCertAKI(self.cert)

    def time_left_on_certificate(self):
        return funcs.time_left_on_certificate(self.cert)

    def time_left_on_certificate_dict(self):
        td = self.time_left_on_certificate()
        d = {}
        d["days"] = td.days
        d["hours"] = td.seconds // 3600
        h = td.seconds // 3600
        m = (td.seconds - h * 3600) // 60
        d["minutes"] = m
        d["seconds"] = td.seconds % 60
        return d


    def x509_not_valid_after(self):
        return funcs.x509_not_valid_after(self.cert)

    def x509_not_valid_before(self):
        return funcs.x509_not_valid_before(self.cert)

    def pubkey_hex(self):
        return funcs.x509_to_pubkey_key(self.cert)

    def subject_dn(self):
        return funcs.x509_to_subject_dn(self.cert)

    def tlsa_rdata_3_1_1(self):
        return "3 1 1 " + self.pubkey_hex()

    def tlsa_rr_name_host(self):
        return "_" + str(self.port) + "." + \
               "_" + self.transport_proto + "." + \
               self.host

    def tlsa_rr_name_fqdn(self):
        return "_" + str(self.port) + "." + \
               "_" + self.transport_proto + "." + \
               self.fqdn + "."

    def tlsa_rr(self):
        return self.tlsa_rr_name_host() + \
               " IN TLSA " + \
               self.tlsa_rdata_3_1_1()

    def tlsa_rr_fqdn(self):
        return self.tlsa_rr_name_fqdn() + \
               " IN TLSA " + \
               self.tlsa_rdata_3_1_1()

    def connect(self):
        """Fetch a certificate, reporting expected connection failures with context."""
        if self.app_protocol in (DANETLSAprotocols.DANETLSA_PEM,
                                 DANETLSAprotocols.DANETLSA_DER):
            return self._connect()
        try:
            return self._connect()
        except (OSError, smtplib.SMTPException, imaplib.IMAP4.error,
                poplib.error_proto, ftplib.Error, EOFError) as err:
            if isinstance(err, socket.gaierror):
                reason = f"hostname lookup failed: {err}"
            elif isinstance(err, TimeoutError):
                reason = f"connection or handshake timed out (timeout: {self.timeout}s)"
            elif isinstance(err, ConnectionRefusedError):
                reason = "connection refused"
            elif isinstance(err, ssl.SSLError):
                reason = f"TLS handshake failed: {err}"
            else:
                reason = str(err) or type(err).__name__
            protocol = DANETLS_protocol_to_str(self.app_protocol)
            raise DANETLSAConnectionError(
                f"Cannot retrieve certificate from {self.fqdn}:{self.port} "
                f"({protocol}): {reason}"
            ) from err

    def _connect(self):
        if self.app_protocol == DANETLSAprotocols.DANETLSA_TLS:
            self.cert_pem = ssl.get_server_certificate((self.fqdn, self.port),
                                                       timeout=self.timeout)
            self.cert_der = ssl.PEM_cert_to_DER_cert(self.cert_pem)

        elif self.app_protocol == DANETLSAprotocols.DANETLSA_SMTP:
            smtp = smtplib.SMTP(host=self.fqdn, port=self.port, timeout=self.timeout)
            smtp.starttls()
            self.cert_der = smtp.sock.getpeercert(binary_form=True)
            self.cert_pem = ssl.DER_cert_to_PEM_cert(self.cert_der)

        elif self.app_protocol == DANETLSAprotocols.DANETLSA_IMAP:
            imap = imaplib.IMAP4(self.fqdn, self.port, timeout=self.timeout)
            imap.starttls()
            self.cert_der = imap.sock.getpeercert(binary_form=True)
            self.cert_pem = ssl.DER_cert_to_PEM_cert(self.cert_der)

        elif self.app_protocol == DANETLSAprotocols.DANETLSA_POP3:
            pop = poplib.POP3(self.fqdn, self.port, self.timeout)
            pop.stls()
            self.cert_der = pop.sock.getpeercert(binary_form=True)
            self.cert_pem = ssl.DER_cert_to_PEM_cert(self.cert_der)

        elif self.app_protocol == DANETLSAprotocols.DANETLSA_PEM:
            with open(self.certfile, "r") as f:
                self.cert_pem = f.read()
            self.cert_der = ssl.PEM_cert_to_DER_cert(self.cert_pem)

        elif self.app_protocol == DANETLSAprotocols.DANETLSA_DER:
            with open(self.certfile, "rb") as f:
                self.cert_der = f.read()
            self.cert_pem = ssl.DER_cert_to_PEM_cert(self.cert_der)

        elif self.app_protocol == DANETLSAprotocols.DANETLSA_FTP:
            ftps = ftplib.FTP_TLS(self.fqdn, timeout=self.timeout)
            ftps.auth()
            self.cert_der = ftps.sock.getpeercert(binary_form=True)
            self.cert_pem = ssl.DER_cert_to_PEM_cert(self.cert_der)

        ### Parsing into X.509 object
        self.cert = crypto.load_certificate(crypto.FILETYPE_ASN1, self.cert_der)

    # Compatibility with callers predating the connect() API.
    engage = connect

    def results_to_dict(self):
        r = {}
        r['fqdn'] = self.fqdn
        r['host'] = self.host
        r['domain'] = self.domain
        r['port'] = self.port
        r['transport_proto'] = self.transport_proto
        r['app_protocol'] = DANETLS_protocol_to_str(self.app_protocol)
        r['subject_dn'] = self.subject_dn()
        r['x509_not_valid_before'] = self.x509_not_valid_before()
        r['x509_not_valid_after'] = self.x509_not_valid_after()
        r['pubkey_hex'] = self.pubkey_hex()
        r['tlsa_rr_name_host'] = self.tlsa_rr_name_host()
        r['tlsa_rr_name_fqdn'] = self.tlsa_rr_name_fqdn()
        r['tlsa_rdata_3_1_1'] = self.tlsa_rdata_3_1_1()
        r['tlsa_rr'] = self.tlsa_rr()
        r['tlsa_rr_fqdn'] = self.tlsa_rr_fqdn()
        r['dns_tlsa'] = self.dns_tlsa()
        r['match_cert_with_tlsa_rr'] = self.match_cert_with_tlsa_rr()
        r['time_left_on_certificate'] = str(self.time_left_on_certificate())
        r['time_left_on_certificate_dict'] = self.time_left_on_certificate_dict()

        return r

# Public aliases retained for existing transip-cmd installations.
DANETLSA_IMAP = DANETLSAprotocols.DANETLSA_IMAP
DANETLSA_POP3 = DANETLSAprotocols.DANETLSA_POP3
DANETLSA_SMTP = DANETLSAprotocols.DANETLSA_SMTP
DANETLSA_TLS = DANETLSAprotocols.DANETLSA_TLS
DANETLSA_PEM = DANETLSAprotocols.DANETLSA_PEM
DANETLSA_DER = DANETLSAprotocols.DANETLSA_DER
DANETLSA_FTP = DANETLSAprotocols.DANETLSA_FTP
DANETLS_protocols = DANETLSA_get_supported_protocols()


class danetlsa(DANETLSA):
    """Compatibility adapter for the original public constructor."""

    def __init__(self, fqdn=None, port=None, domain=None,
                 tlsa_protocol='tcp', probe_protocol=DANETLSA_TLS,
                 certfile=None, timeout=10, *, protocol=None):
        if protocol is not None:
            probe_protocol = protocol
        super().__init__(fqdn=fqdn, port=port, domain=domain,
                         transport_proto=tlsa_protocol,
                         app_protocol=probe_protocol,
                         certfile=certfile, timeout=timeout)


def execute_test(fqdn=None, port=25, domain=None,
                    transport_proto='tcp',
                    app_protocol=None, certfile=None,
                    verbose=False):
    if verbose:
        print(f"===")
        print(f"- input:")
        print(f"t fqdn           : {fqdn}")
        print(f"t port           : {port}")
        print(f"t domain         : {domain}")
        print(f"t transport_proto: {transport_proto}")
        print(f"t app_protocol   : {DANETLS_protocol_to_str(app_protocol)}")
        print("- running:")

    d = DANETLSA(fqdn=fqdn, port=port,
                            transport_proto=transport_proto,
                            app_protocol=app_protocol, certfile=certfile)
    d.connect()

    if verbose:
        print("- output:")
        print("Subject DN       :", d.subject_dn())
        print("Not valid after  :", d.x509_not_valid_after())
        print("Time left        :", d.time_left_on_certificate())
        print("Time left        :", d.time_left_on_certificate_dict())
        print("Pub key hex      :", d.pubkey_hex())
        print("TLSA RR host     :", d.tlsa_rr_name_host())
        print("TLSA RR name     :", d.tlsa_rr_name_fqdn())
        print("TLSA rdata 3 1 1 :", d.tlsa_rdata_3_1_1())
        print("TLSA RR          :", d.tlsa_rr())
        print("TLSA RR with FQDN:", d.tlsa_rr_fqdn())
        print("DNS results      :", d.dns_tlsa())
        print("Match DNS w/ X509:", d.match_cert_with_tlsa_rr())
        print("-- done.")


### Start up
if __name__ == "__main__":
    import tests

    tests.runtest()
