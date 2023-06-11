#!/usr/bin/env python3

from pyDANETLSA import DANETLSAprotocols, DANETLSA, DANETLSA_get_supported_protocols, DANETLS_protocol_to_str


print("Protocol support list:", DANETLSA_get_supported_protocols())


def execute_test(fqdn=None, port=None, domain=None, tlsa_protocol='tcp', 
                 probe_protocol=None, certfile=None):
    print("===")
    print("- input:")
    print("t fqdn           :", fqdn)
    print("t port           :", port)
    print("t domain         :", domain)
    print("t tlsa_protocol  :", tlsa_protocol)
    print("t probe_protocol : {}({})".format(DANETLS_protocol_to_str(probe_protocol), probe_protocol))


    print("- run:")
    d = DANETLSA(fqdn=fqdn, port=port,
                            tlsa_protocol=tlsa_protocol,
                            probe_protocol=probe_protocol, certfile=certfile)

    print("i FQDN           :", d.fqdn)
    print("i Host           :", d.host)
    print("i Domain         :", d.domain)
    d.connect()

    print("- output:")
    print("Subject DN       :", d.subject_dn())
    print("Pub key hex      :", d.pubkey_hex())
    print("TLSA RR name/host:", d.tlsa_rr_name_host())
    print("TLSA RR name/host:", d.tlsa_rr_name_fqdn())
    print("TLSA rdata 3 1 1 :", d.tlsa_rdata_3_1_1())
    print("TLSA RR          :", d.tlsa_rr())
    print("TLSA RR with FQDN:", d.tlsa_rr_fqdn())
    print("-- done.")
    print("DNS: ",              d.dns_tlsa())
    print("Match DNS TLSA records with X.509 certificate:", d.match_cert_with_tlsa_rr())
    print("----------------")



try:
    # Expected to fail and raise an exception
    execute_test(fqdn='foobar.koeroo.net.', port=777, probe_protocol=DANETLSAprotocols.DANETLSA_TLS,
                 certfile="dont_exists.pem")
except Exception as e:
    print(e)

try:
    execute_test(fqdn='foobar.koeroo.net.', port=777, probe_protocol=DANETLSAprotocols.DANETLSA_PEM,
                certfile="testcert/dummy.pem")
except Exception as e:
    print(e)

try:
    execute_test(fqdn='foobar.koeroo.net.', port=777, probe_protocol=DANETLSAprotocols.DANETLSA_DER,
                certfile="testcert/dummy.der")
except Exception as e:
    print(e)


execute_test(fqdn='smtp.koeroo.net',    port=25,  probe_protocol=DANETLSAprotocols.DANETLSA_SMTP)
execute_test(fqdn='mx.ncsc.nl',         port=25,  probe_protocol=DANETLSAprotocols.DANETLSA_SMTP)
execute_test(fqdn='mail.koeroo.net.',   port=143, probe_protocol=DANETLSAprotocols.DANETLSA_IMAP)
execute_test(fqdn='mail.koeroo.net.',   port=465, probe_protocol=DANETLSAprotocols.DANETLSA_TLS)
execute_test(fqdn='pop.kpnmail.nl',     port=110, probe_protocol=DANETLSAprotocols.DANETLSA_POP3)

execute_test(fqdn='test.rebex.net.',     port=21, probe_protocol=DANETLSAprotocols.DANETLSA_FTP)
