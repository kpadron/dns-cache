import struct
import dnslib

class Packet:
    pass

class Request:
    def __init__(self, query: bytes):
        """
        """
        self.header = dnslib.DNSHeader.parse(query)