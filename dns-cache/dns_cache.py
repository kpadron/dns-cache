import typing
import itertools as it
from collections import OrderedDict

__all__ = \
[
    'LruCache',
]

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

    def __getitem__(self, key: typing.Hashable) -> typing.Any:
        """Lookup a value in the cache using a key.

        If the entry exists in the cache it is updated to be the most-recently-used.
        """
        try:
            value = super().__getitem__(key)
            self.move_to_end(key)
            self._lookups += 1
            self._hits += 1
            return value

        except KeyError:
            self._lookups += 1
            raise

    def __setitem__(self,  key: typing.Hashable, value: typing.Hashable) -> None:
        """Set a value to the cache using a key.

        If the entry already existed in the cache it is updated to be the most-recently-used.

        If the operation would cause the cache to grow beyond its max size then the
        least-recently-used cache entry is evicted.
        """
        super().__setitem__(key, value)
        self.trim()

    def get(self, key: typing.Hashable, default: typing.Any = None) -> typing.Any:
        """Returns the value mapped from key if it exists otherwise return default.
        """
        try: return self[key]
        except KeyError: return default

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

