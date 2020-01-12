import asyncio as aio
import itertools as it
import struct
import typing
from asyncio import Event
from collections import OrderedDict
from collections.abc import Collection, Container, Sequence

__all__ = \
[
    'CollectionView',
    'ContainerView',
    'LruCache',
    'SequenceView',
    'StateEvent',
    'cancel_all',
    'full_cancel',
    'get_short',
    'set_short',
    'wait_first',
]


class ContainerView(Container):
    """Provides a read-only view for an arbitrary container.
    """
    __slots__ = '_container'

    def __init__(self, container: typing.Container) -> None:
        self._container = container

    def __contains__(self, x) -> bool:
        return x in self._container

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self._container!r})'


class CollectionView(ContainerView, Collection):
    """Provides a read-only view for an arbitrary collection.
    """
    __slots__ = ()

    def __iter__(self) -> typing.Iterator:
        return iter(self._container)

    def __len__(self) -> int:
        return len(self._container)


class SequenceView(CollectionView, Sequence):
    """Provides a read-only view for an arbitrary sequence.
    """
    __slots__ = ()

    def __getitem__(self, index: int) -> typing.Any:
        return self._container[index]


class LruCache(OrderedDict):
    """Generic cache class utilizing the least-recently-used eviction policy.
    """
    def __init__(self, size: int = None) -> None:
        """Initialize a LruCache instance.

        Args:
            size: The maximum size the cache is allowed to grow to.
                  If unspecified or None then the cache size is unbounded.
        """
        super().__init__()

        self.size = size

        self._lookups = 0
        self._hits = 0
        self._evictions = 0

    def get(self, key: typing.Hashable, default: typing.Any = None) -> typing.Any:
        """Get a value from the cache using a key.

        If the entry exists in the cache it is updated to be the most-recently-used.
        """
        try:
            value = self[key]
            self.move_to_end(key)
            self._lookups += 1
            self._hits += 1
            return value

        except KeyError:
            self._lookups += 1
            return default

    def set(self, key: typing.Hashable, value: typing.Hashable) -> None:
        """Set a value in the cache using a key.

        If the entry already existed in the cache it is updated to be the most-recently-used.

        If the operation would cause the cache to grow beyond its max size then the
        least-recently-used cache entries are evicted.
        """
        self[key] = value
        self.trim()

    def trim(self) -> None:
        """Ensures the cache is bounded by the size attribute removing entries if necessary.
        """
        if self._size is not None:
            while len(self) > self._size:
                del self[next(iter(self))]
                self._evictions += 1

    def least_recent(self, n: int = 1) -> typing.Iterator:
        """Returns an iterator of the n least-recently-used items.
        """
        n = 0 if n <= 0 else min(n, len(self))
        return it.islice(iter(self.items()), n)

    def most_recent(self, n: int = 1) -> typing.Iterator:
        """Returns an iterator over the n most-recently-used items.
        """
        n = 0 if n <= 0 else min(n, len(self))
        return it.islice(reversed(self.items()), n)

    @property
    def size(self) -> int:
        """Returns the maximum size the instance is allowed to grow to.
        """
        return self._size

    @size.setter
    def size(self, value: typing.Union[None, int]) -> None:
        """Sets the maximum size the instance is allowed to grow to.

        Setting to None makes the size unbounded.
        """
        value = None if value is None else max(int(value), 0)
        self._size = value

    @property
    def lookups(self) -> int:
        """Returns the total number of lookup operation performed on the instance.
        """
        return self._lookups

    @property
    def hits(self) -> int:
        """Returns the total number of cache hits for the instance.
        """
        return self._hits

    @property
    def misses(self) -> int:
        """Returns the total number of cache misses for the instance.
        """
        return self._lookups - self._hits

    @property
    def evictions(self) -> int:
        """Returns the total number of cache evictions for the instance.
        """
        return self._evictions

    @property
    def hit_ratio(self) -> float:
        """Returns the current cache hit ratio for the instance.
        """
        try: return 1.00 * self._hits / self._lookups
        except ZeroDivisionError: return 0

    @property
    def miss_ratio(self) -> float:
        """Returns the current cache miss ratio for the instance.
        """
        return 1.00 - self.hit_ratio

    @property
    def stats(self) -> typing.Mapping[str, typing.Union[None, int, float]]:
        """Returns a mapping of current cache statistics.
        """
        keys = ('size', 'lookups', 'hits', 'misses', 'evictions', 'hit_ratio', 'miss_ratio')
        return {key: getattr(self, key) for key in keys}


class StateEvent(Event):
    """An async event that can be waited for both state changes.

    Extends asyncio.Event to provide:
        - async def wait_true()
        - async def wait_false()
    """
    def __init__(self) -> None:
        super().__init__()
        self.__ievent = Event()
        self.__ievent.set()

    async def wait_true(self) -> bool:
        """Wait until the internal flag is true.
        """
        return await self.wait()

    async def wait_false(self) -> bool:
        """Wait until the internal flag is false.
        """
        return await self.__ievent.wait()

    def set(self) -> None:
        super().set()
        self.__ievent.clear()

    def clear(self) -> None:
        super().clear()
        self.__ievent.set()


def get_short(data: bytes, offset: int = 0) -> int:
    """Returns a short (16-bit unsigned integer) by reading 2-bytes of data.

    Note: The short is expected to be stored in NBO when reading data.

    Args:
        data: The bytes-like object to read (must be at least 2-bytes long starting at offset).
        offset: The byte offset to start the 2-byte read.

    Raises:
        TypeError: When given unsupported input types.
        ValueError: When given correct input types with bad values.
    """
    try: 
        return struct.unpack('!H', memoryview(data)[offset:offset+2])[0]
    except struct.error:
        raise ValueError('data - must be at least 2-bytes long starting at offset')

def set_short(data: bytearray, value: int, offset: int = 0) -> None:
    """Writes a short (16-bit unsigned integer) by writing 2-bytes at offset in data.

    Note: The short is stored in NBO when writing data.

    Args:
        data: The mutable bytes-like object to write to (must be at least 2-bytes long starting at offset).
        value: The short integer value to write to data.
        offset: The byte offset to start the 2-byte write.

    Raises:
        TypeError: When given unsupported input types.
        ValueError: When given correct input types with bad values.
    """
    memoryview(data)[offset:offset+2] = struct.pack('!H', int(value) & 0xffff)

async def full_cancel(future: aio.Future) -> None:
    """Fully cancels a future by cancelling then awaiting it.
    """
    if future.cancel():
        try: await future
        except aio.CancelledError: pass

async def cancel_all(futures: typing.Iterable[aio.Future]) -> None:
    """Fully cancels all futures in a iterable of futures.
    """
    cancelled = []

    for future in futures:
        if future.cancel():
            cancelled.append(future)

    for future in cancelled:
        try: await future
        except aio.CancelledError: pass

async def wait_first(futures: typing.Iterable[aio.Future], cancel_pending: bool = True) -> aio.Future:
    """Waits for the first future in futures to complete and returns it.

    Args:
        futures: The iterable of futures to wait on.
        cancel_pending: Whether to cancel the pending futures after waiting.

    Returns:
        The first future to complete.
    """
    # Wait for the first future to complete
    (done, pending) = await aio.wait(futures, return_when=aio.FIRST_COMPLETED)

    # Cancel the unfinished futures
    if cancel_pending:
        await cancel_all(pending)

    # Return the first future that finished
    return done.pop()
