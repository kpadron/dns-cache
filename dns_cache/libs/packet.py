import itertools as it
import struct
import time
from collections.abc import Hashable as _Hashable
from typing import Iterable, Iterator, Optional, Sequence

import dnslib as dl
from dnslib import RCODE, RR, DNSQuestion, DNSRecord

__all__ = \
[
    'RCODE',
    'NOERROR',
    'FORMERR',
    'SERVFAIL',
    'Question',
    'Answer',
    'Packet',
]

NOERROR = RCODE.NOERROR
FORMERR = RCODE.FORMERR
SERVFAIL = RCODE.SERVFAIL


class Question(DNSQuestion, _Hashable):
    """DNS question class."""
    def __init__(self, qname: str, qtype: str = 'A', qclass: str = 'IN') -> None:
        """
        Initializes a Question instance.

        Args:
            qname: The domain or host name to lookup records for.
            qtype: The type of lookup to perform.
            qclass: The class of records to lookup.
        """
        super().__init__(qname, getattr(dl.QTYPE, qtype), getattr(dl.CLASS, qclass))

    def __hash__(self) -> int:
        return hash((self.qname, self.qtype))

    def __eq__(self, other) -> bool:
        attrs = ('qname', 'qtype', 'qclass')
        return all(getattr(self, attr) == getattr(other, attr) for attr in attrs)

    def to_query(self, qid: Optional[int] = None) -> bytes:
        """Generates a new DNS query packet from this question."""
        buffer = dl.DNSBuffer()
        dl.DNSHeader(id=qid, q=1).pack(buffer)
        self.pack(buffer)
        return buffer.data


class Answer:
    """DNS answer class."""
    def __init__(
        self,
        rcode: int = NOERROR,
        answer: Iterable[RR] = (),
        authority: Iterable[RR] = (),
        additional: Iterable[RR] = ()) -> None:
        """
        Initializes a Answer instance.

        Args:
            rcode: The return code from the answer packet.
            answer: A iterable of DNS resource records from the answer section.
            authority: A iterable of DNS resource records from the authority section.
            additional: A iterable of DNS resource records from the additional section.
        """
        self._time = time.monotonic()

        self._rcode = int(rcode)
        self._answer = tuple(self._strip_records(answer))
        self._authority = tuple(self._strip_records(authority))
        self._additional = tuple(self._strip_records(additional))

        self._min_ttl = None

    def __repr__(self) -> str:
        return f'<Answer: rcode={self.rcode!r} answer={self.answer!r}>'

    def stamp(self) -> None:
        """Adjusts the ttl fields in instance records based on the current time."""
        now = time.monotonic()
        diff = int(now - self._time)

        if diff > 0:
            self._time = now

            for record in self.records:
                record.ttl = max(record.ttl - diff, 0)

            if self._min_ttl is not None:
                self._min_ttl = max(self._min_ttl - diff, 0)

    @property
    def rcode(self) -> int:
        """Returns the rcode for the instance."""
        return self._rcode

    @property
    def answer(self) -> Sequence[RR]:
        """Returns a sequence of all instance answer records."""
        return self._answer

    @property
    def authority(self) -> Sequence[RR]:
        """Returns a sequence of all instance authority records."""
        return self._authority

    @property
    def additional(self) -> Sequence[RR]:
        """Returns a sequence of all instance additional records."""
        return self._additional

    @property
    def records(self) -> Iterable[RR]:
        """Returns an iterable of all instance records."""
        return it.chain(self.answer, self.authority, self.additional)

    @property
    def ttl(self) -> float:
        """Returns the minimum ttl of all instance records."""
        if self._min_ttl is None:
            self._min_ttl = min(record.ttl for record in self.records)

        return self._min_ttl

    @property
    def expired(self) -> bool:
        """Returns whether the instance has expired or not."""
        return time.monotonic() > self._time + self.ttl

    @staticmethod
    def _strip_records(records: Iterable[RR]) -> Iterator[RR]:
        """Returns a iterator of records with all unsupported records removed."""
        for record in records:
            if record.rtype == dl.QTYPE.OPT:
                continue

            yield record


class Packet(DNSRecord):
    """DNS packet class."""

    @classmethod
    def decode(cls, data: bytes) -> 'Packet':
        """Initialize a Packet instance from DNS packet data."""
        try:
            return cls.parse(data)

        except dl.DNSError:
            return None

    def encode(self) -> bytes:
        """Encode the instance to DNS packet data."""
        return self.pack()

    def get_question(self) -> Question:
        """Extract the question from the instance."""
        q = self.q
        return Question(q.qname, dl.QTYPE[q.qtype], dl.CLASS[q.qclass])

    def get_answer(self) -> Answer:
        """Extract the answer from the instance."""
        return Answer(self.header.rcode, self.rr, self.auth, self.ar)

    def set_answer(self, answer: Answer) -> None:
        """Set the answer resource records for this instance."""
        self.set_response(answer.rcode)
        self.rr = list(answer.answer)
        self.auth = list(answer.authority)
        self.ar = list(answer.additional)

    def set_response(self, rcode: int = NOERROR) -> None:
        """Marks the packet as a query response and sets the rcode."""
        self.header.rcode = rcode
        self.header.qr = 1
        self.header.aa = 0
        self.header.ad = 0
        self.header.ra = 1
