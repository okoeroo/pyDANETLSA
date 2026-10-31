import sys
from enum import Enum
from dataclasses import dataclass, field
import dns.resolver
import dns.asyncresolver


class DNSERRORS(Enum):
    NOERROR = 1,
    NXDOMAIN = 2,
    SERVFAIL = 3,
    TIMEOUT = 4,
    ERROR = 5


# Very weird config interface, but this is what dnspython does:
# only one port to be set, as the dict only allows for one dict.
@dataclass
class DnsPythonConfig:
    raw: str
    nameservers: list[str] = field(init=False)
    nameservers_port: dict = field(init=False)

    def split_raw_str_to_nameservers_list(self, raw_ns_str) -> list[str]:
        # Split nameservers by comma, and only take the left side of a colon, if
        # it exists
        return [ns.split(":")[0] for ns in raw_ns_str.split(",")]

    def split_raw_str_to_nameserver_port_dict(self, raw_ns_str) -> dict:
        # Split the nameserver by comma, and only for the elements with colon, add
        # the nameserver and port key/value to the dict
        ns_elems_dict = {}
        for ns in raw_ns_str.split(","):
            if ":" in ns:
                ns_elems_dict[ns.split(":")[0]] = int(ns.split(":")[1])

        return ns_elems_dict

    def __post_init__(self):
        raw_ns_str = self.raw

        if raw_ns_str is not None:
            self.nameservers = self.split_raw_str_to_nameservers_list(self.raw) 
            self.nameservers_port = self.split_raw_str_to_nameserver_port_dict(self.raw)
    
    def fetch_config_tuple(self):
        for nameserver, port in self.nameservers_port.items():
            return nameserver, port


def dns_query(fqdn: str, r_type: str,
                dns_config: DnsPythonConfig,
                verbose: bool = False) -> tuple[DNSERRORS, str]:

    if verbose:
        print(f"DNS query (verbose): FQDN={fqdn} RRtype={r_type}", file=sys.stderr)

    try:
        resolver = dns.resolver.Resolver()

        if dns_config is not None:
            resolver.nameservers = dns_config.nameservers
            resolver.nameserver_ports = dns_config.nameservers_port

        resolver.timeout = 30
        resolver.lifetime = 30

        # Query
        answers = resolver.query(fqdn, r_type)
        rrset = [str(rr) for rr in answers]

        if verbose:
            rrset_str = ",".join(rrset)
            print(f"DNS query (verbose): FQDN={fqdn} RRtype={r_type} RRset={rrset_str}", file=sys.stderr)

        return DNSERRORS.NOERROR, answers


    except dns.resolver.NXDOMAIN:
        print(f"DNS query: warning=NXDOMAIN FQDN={fqdn} RRtype={r_type}", file=sys.stderr)
        return DNSERRORS.NXDOMAIN, None

    except dns.resolver.NoAnswer:
        print(f"DNS query: warning=SERVFAIL FQDN={fqdn} RRtype={r_type}", file=sys.stderr)
        return DNSERRORS.SERVFAIL, None

    except dns.exception.Timeout:
        print(f"DNS query: error=TIMEOUT FQDN={fqdn} RRtype={r_type}", file=sys.stderr)
        return DNSERRORS.TIMEOUT, None

    except EOFError:
        print(f"DNS query: error=EOF FQDN={fqdn} RRtype={r_type}", file=sys.stderr)
        return DNSERRORS.ERROR, None

    except Exception as e:
        print(f"DNS query: error='{e}' FQDN={fqdn} RRtype={r_type}", file=sys.stderr)
        return DNSERRORS.ERROR, None


async def a_dns_query(fqdn: str, r_type: str,
                      dns_config: DnsPythonConfig,
                      verbose: bool = False) -> tuple[DNSERRORS, str]:

    if verbose:
        print(f"DNS query (verbose): FQDN={fqdn} RRtype={r_type}", file=sys.stderr)

    try:
        resolver = dns.asyncresolver.Resolver()

        resolver.nameservers = dns_config.nameservers
        resolver.nameserver_ports = dns_config.nameservers_port

        # Query
        answers = await resolver.resolve(fqdn, r_type)
        rrset = [str(rr) for rr in answers]

        if verbose:
            rrset_str = ",".join(rrset)
            print(f"DNS query (verbose): FQDN={fqdn} RRtype={r_type} RRset={rrset_str}", file=sys.stderr)

        return DNSERRORS.NOERROR, answers


    except dns.resolver.NXDOMAIN:
        print(f"DNS query: warning=NXDOMAIN FQDN={fqdn} RRtype={r_type}", file=sys.stderr)
        return DNSERRORS.NXDOMAIN, None

    except dns.resolver.NoAnswer:
        print(f"DNS query: warning=SERVFAIL FQDN={fqdn} RRtype={r_type}", file=sys.stderr)
        return DNSERRORS.SERVFAIL, None

    except dns.exception.Timeout:
        print(f"DNS query: error=TIMEOUT FQDN={fqdn} RRtype={r_type}", file=sys.stderr)
        return DNSERRORS.TIMEOUT, None

    except EOFError:
        print(f"DNS query: error=EOF FQDN={fqdn} RRtype={r_type}", file=sys.stderr)
        return DNSERRORS.ERROR, None

    except Exception as e:
        print(f"DNS query: error='{e}' FQDN={fqdn} RRtype={r_type}", file=sys.stderr)
        return DNSERRORS.ERROR, None

class TLSAResolutionError(Exception):
    """TLSA owner could not be resolved safely."""


def resolve_tlsa_owner(fqdn, max_hops=16):
    """Follow CNAMEs explicitly; never treat lookup failures as absence."""
    import dns.name
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 10
    current = dns.name.from_text(fqdn).canonicalize()
    visited = set()
    chain = [current.to_text()]
    for _ in range(max_hops + 1):
        if current in visited:
            raise TLSAResolutionError(f"CNAME loop at {current}")
        visited.add(current)
        try:
            answer = resolver.resolve(current, "CNAME")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return current.to_text(), chain
        except dns.exception.DNSException as err:
            raise TLSAResolutionError(f"Cannot resolve CNAME for {current}: {err}") from err
        current = answer[0].target.canonicalize()
        chain.append(current.to_text())
    raise TLSAResolutionError(f"CNAME chain exceeds {max_hops} hops: {fqdn}")
