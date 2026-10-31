#!/usr/bin/env python3

import sys
import json
import syslog

from pyDANETLSA import DANETLSA
from pyDANETLSA import DANETLS_protocol_to_str, str_to_DANETLS_protocol

from .libs.configuration import arguments, is_startup_clean


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
        print(f"t transport_proto  : {transport_proto}")
        print(f"t app_protocol : {DANETLS_protocol_to_str(app_protocol)}")
        print("- running:")

    d = DANETLSA(fqdn=fqdn, port=port,
                            transport_proto=transport_proto,
                            app_protocol=app_protocol, certfile=certfile)
    d.connect()

    if verbose:
        print("- output:")
        print("Subject DN       :", d.subject_dn())
        print("Not valid after  :", d.x509_not_valid_after())
        print("Time left on cert:", d.time_left_on_certificate())
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


    # On match, True. Otherwise False
    return d.results_to_dict()


def monitor(args):
    # Openlog with ident
    if args.syslog_ident is not None:
        syslog.openlog(args.syslog_ident)

    res = execute_test(fqdn=args.fqdn,
                        port=args.port,
                        transport_proto=args.transport.lower(),
                        app_protocol=str_to_DANETLS_protocol(args.protocol),
                        verbose=args.verbose)


    syslog.syslog(syslog.LOG_INFO|syslog.LOG_DAEMON, json.dumps(res))
    print(json.dumps(res))

    if res['match_cert_with_tlsa_rr']:
        return 0
    else:
        return 1


if __name__ == "__main__":
    args = arguments()
    if not is_startup_clean(args):
        sys.exit(1)

    res = monitor(args)
    sys.exit(res)
