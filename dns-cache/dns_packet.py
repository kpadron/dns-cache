import itertools as it
import struct
import time
import typing

import dnslib as dl

__all__ = \
[
    'Packet',
    'Question',
    'Answer',
]

NOERROR = dl.RCODE.NOERROR
FORMERR = dl.RCODE.FORMERR
SERVFAIL = dl.RCODE.SERVFAIL
OPT = dl.QTYPE.OPT

class Packet(dl.DNSRecord):
    """DNS packet class.
    """
    @classmethod
    def question(cls, qname: str, qtype: str = 'A', qclass: str = 'IN') -> 'Packet':
        """Initialize a packet from a simple question.
        """
        return cls(q=Question(qname, getattr(dl.QTYPE, qtype), getattr(dl.CLASS, qclass)))

    @classmethod
    def decode(cls, data: bytes) -> 'Packet':
        """Initialize a Packet instance from DNS packet data.
        """
        try:
            return cls.parse(data)

        except dl.DNSError:
            return None

    def encode(self) -> bytes:
        """Encode the instance to DNS packet data.
        """
        return self.pack()

    def get_question(self) -> 'Question':
        """Extract the question from the instance.
        """
        q = self.q
        return Question(q.qname, q.qtype, q.qclass)

    def get_answer(self) -> 'Answer':
        """Extract the answer from the instance.
        """
        return Answer(self.header.rcode, self.rr, self.auth, self.ar)

    def set_answer(self, answer: 'Answer') -> None:
        """Set the answer resource records for this instance.
        """
        self.set_response(answer.rcode)
        self.rr = list(answer.answer())
        self.auth = list(answer.authority())
        self.ar = list(answer.additional())

    def set_response(self, rcode: int = NOERROR) -> None:
        """Marks the packet as a query response and sets the rcode.
        """
        self.header.rcode = rcode
        self.header.qr = 1
        self.header.aa = 1
        self.header.ra = 1


class Question(dl.DNSQuestion):
    """DNS question class.
    """
    def __hash__(self) -> int:
        return hash((self.qname, self.qtype))

    def __eq__(self, other) -> bool:
        attrs = ('qname', 'qtype', 'qclass')
        return all(getattr(self, attr) == getattr(other, attr) for attr in attrs)

    def to_query(self, id: int = None) -> bytes:
        """Generate a new DNS query packet from this question.
        """
        buffer = dl.DNSBuffer()
        dl.DNSHeader(id=id, q=1).pack(buffer)
        self.pack(buffer)
        return buffer.data


class Answer:
    """DNS answer class.
    """
    def __init__(self, rcode: int = NOERROR, answer: typing.Iterable[dl.RR] = [], authority: typing.Iterable[dl.RR] = [], additional: typing.Iterable[dl.RR] = []) -> None:
        """Initialize the Answer instance.
        """
        self._time = time.monotonic()

        self._rcode = rcode
        self._answer = list(self._strip_records(answer))
        self._authority = list(self._strip_records(authority))
        self._additional = list(self._strip_records(additional))

        self._min_ttl = None

    def __repr__(self) -> str:
        return f'<Answer: rcode={self.rcode!r} records={list(self.records())!r}>'

    @staticmethod
    def _strip_records(records: typing.Iterable[dl.RR]) -> typing.Iterator[dl.RR]:
        """Returns a iterator of records with all unsupported records removed.
        """
        for record in records:
            if record.rtype == OPT:
                continue

            yield record

    @property
    def rcode(self) -> int:
        """Returns the rcode for the instance.
        """
        return self._rcode

    def answer(self) -> typing.Iterator[dl.RR]:
        """Returns an iterator over all answer records.
        """
        return iter(self._answer)

    def authority(self) -> typing.Iterator[dl.RR]:
        """Returns an iterator over all authority records.
        """
        return iter(self._authority)

    def additional(self) -> typing.Iterator[dl.RR]:
        """Returns an iterator over all additional records.
        """
        return iter(self._additional)

    def records(self) -> typing.Iterator[dl.RR]:
        """Returns an iterator over records in all sections.
        """
        for section in (self.answer(), self.authority(), self.additional()):
            yield from section

    @property
    def ttl(self) -> float:
        """Returns the minimum ttl of all instance records.
        """
        if self._min_ttl is None:
            self._min_ttl = min(record.ttl for record in self.records())

        return self._min_ttl

    @property
    def age(self) -> float:
        """Returns the age of the instance.
        """
        return time.monotonic() - self._time

    @property
    def expiration(self) -> float:
        """Returns the time at which the instance will expire.
        """
        return self._time + self.ttl

    @property
    def time_left(self) -> float:
        """Returns time left until the instance is expired.
        """
        return self.expiration - self.age

    @property
    def expired(self) -> bool:
        """Returns whether the instance has expired or not.
        """
        return self.age > self.ttl
