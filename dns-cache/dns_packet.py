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

FORMERR = dl.RCODE.FORMERR
NOTIMP = dl.RCODE.NOTIMP
OPT = dl.QTYPE.OPT

class Packet(dl.DNSRecord):
    """DNS packet class.
    """

    @classmethod
    def question(cls, q):
        pass

    @classmethod
    def from_data(cls, data: bytes) -> 'Packet':
        """Initialize a Packet instance from DNS packet data.
        """
        try:
            p = super().parse(data)

            if len(p.questions) != 1:
                r = p.reply()
                r.header.rcode = FORMERR
                return r

            return p

        except dl.DNSError:
            return None

    def get_question(self) -> 'Question':
        """Extract the question from the instance.
        """
        q = self.q
        return Question(q.qname, q.qclass, q.qtype)

    def get_answer(self) -> 'Answer':
        """Extract the answer from the instance.
        """
        return Answer()

class Question(dl.DNSQuestion):
    def __hash__(self) -> int:
        return hash((self.qname, self.qclass))

    def __eq__(self, other) -> bool:
        attrs = ('qname', 'qclass', 'qtype')
        return all(getattr(self, attr) == getattr(other, attr) for attr in attrs)

class Answer:
    def __init__(self, answer: typing.Iterable[dl.RR], authority: typing.Iterable[dl.RR], additional: typing.Iterable[dl.RR]) -> None:
        """Initialize the Answer instance.
        """
        self._time = time.monotonic()

        self._answer = list(self._strip_records(answer))
        self._authority = list(self._strip_records(authority))
        self._additional = list(self._strip_records(additional))

        self._min_ttl = min(record.ttl for record in self.records())

    @staticmethod
    def _strip_records(records: typing.Iterable[dl.RR]) -> typing.Iterator[dl.RR]:
        """Returns a iterator of records with all unsupported records removed.
        """
        for record in records:
            if record.rtype == OPT:
                continue

            yield record

    def answer(self) -> typing.Iterator:
        """Returns an iterator over all answer records.
        """
        return iter(self._answer)

    def authority(self) -> typing.Iterator:
        """Returns an iterator over all authority records.
        """
        return iter(self._authority)

    def additional(self) -> typing.Iterator:
        """Returns an iterator over all additional records.
        """
        return iter(self._additional)

    def sections(self) -> typing.Iterator:
        """Returns an iterator over all sections.
        """
        return it.chain(self._answers, self._authority, self._additional)

    def records(self) -> typing.Iterator:
        """Returns an iterator over records in all sections.
        """
        return it.chain.from_iterable(self.sections())

    @property
    def ttl(self) -> float:
        """Returns the minimum ttl of all instance records.
        """
        return self._min_ttl

    @property
    def age(self) -> float:
        """Returns the age of the instance.
        """
        return time.time() - self._time

    @property
    def expiration(self) -> float:
        """Returns the time at which the instance will expire.
        """
        return self._time + self._min_ttl

    @property
    def time_left(self) -> float:
        """Returns time left until the instance is expired.
        """
        return self.expiration - self.age

    @property
    def expired(self) -> bool:
        """Returns whether the instance has expired or not.
        """
        return self.age > self._min_ttl
