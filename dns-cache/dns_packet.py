import struct
import dnslib

class DnsQuery(dnslib.DNSQuestion):
    def __hash__(self):
        return hash((self.qname, self.qtype))

class DnsRequest(dnslib.DNSRecord):
    """
    """
    @classmethod
    def from_packet(cls, packet: bytes) -> 'DnsRequest':
        """Generate a DnsRequest instance from a DNS query packet.

        Args:
            packet: The DNS query packet to parse.

        Returns:
            The relevant DnsRequest instance or None on failure.
        """
        try:
            request = cls.parse(packet)

            if len(request.questions) != 1:
                return None

            return request

        except Exception:
            return None

    def get_query(self):
        """
        """
        return 

class DnsResponse(dnslib.DNSRecord):
    """
    """
    @classmethod
    def from_packet(cls, packet: bytes) -> 'DnsResponse':
        """
        """
        return cls.parse(packet)