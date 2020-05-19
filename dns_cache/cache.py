from abc import ABC, abstractmethod
from collections import OrderedDict, defaultdict
from itertools import islice
from random import sample
from typing import (Any, Hashable, Iterable, Iterator, Mapping, Optional,
                    Tuple, Union)

__all__ = \
    (
        'AbstractCache',
        'RandomCache',
        'LruCache',
        'LfuCache',
    )


class AbstractCache(ABC):
    """
    Generic cache abstract base class.

    Pure Virtual Methods:
        __len__: Returns the current length of the cache.
        __iter__: Returns a iterator over the cache items.
        get_entry: Lookup a value in the cache updating tracking.
        set_entry: Add a value to the cache updating tracking.
        del_entry: Removes a value from the cache updating tracking.
        _get_evictees: Returns a iterable of keys that should be evicted next.
    """

    __slots__ = \
        (
            '_size',
            '_lookups',
            '_hits',
            '_evictions',
        )

    def __init__(self, size: Optional[int] = None) -> None:
        """Initializes a AbstractCache instance."""
        self.size = size

        self._lookups = 0
        self._hits = 0
        self._evictions = 0

    @abstractmethod
    def __len__(self) -> int:
        """Returns the current length of the instance."""
        raise NotImplementedError

    @abstractmethod
    def __iter__(self) -> Iterator[Tuple[Hashable, Any]]:
        """Returns a iterator over the cache items."""
        raise NotImplementedError

    @property
    def size(self) -> Optional[int]:
        """Returns the maximum size the instance is allowed to grow to."""
        return self._size

    @size.setter
    def size(self, value: Optional[int]) -> None:
        """
        Sets the maximum size the instance is allowed to grow to.

        Setting to None makes the size unbounded.
        """
        if value is not None:
            value = max(int(value), 0)

        self._size = value

    @property
    def lookups(self) -> int:
        """Returns the total number of lookup operation performed on the instance."""
        return self._lookups

    @property
    def hits(self) -> int:
        """Returns the total number of cache hits for the instance."""
        return self._hits

    @property
    def misses(self) -> int:
        """Returns the total number of cache misses for the instance."""
        return self._lookups - self._hits

    @property
    def evictions(self) -> int:
        """Returns the total number of cache evictions for the instance."""
        return self._evictions

    @property
    def hit_ratio(self) -> float:
        """Returns the current cache hit ratio for the instance."""
        try: return 1.0 * self._hits / self._lookups
        except ZeroDivisionError: return 0.0

    @property
    def miss_ratio(self) -> float:
        """Returns the current cache miss ratio for the instance."""
        try: return 1.0 * self.misses / self._lookups
        except ZeroDivisionError: return 0.0

    @property
    def stats(self) -> Mapping[str, Union[None, int, float]]:
        """Returns a mapping of current cache statistics."""
        keys = ('size', 'lookups', 'hits', 'misses', 'evictions', 'hit_ratio', 'miss_ratio')
        mapping = {'len': len(self)}
        mapping.update({key: getattr(self, key) for key in keys})
        return mapping

    def trim(self) -> None:
        """Ensures the cache is bounded by the size attribute removing entries if necessary."""
        if self._size is not None:
            diff = len(self) - self._size
            if diff > 0:
                keys = list(self._get_evictees(diff))

                for k in keys:
                    self.del_entry(k)

                self._evictions += diff

    @abstractmethod
    def get_entry(self, key: Hashable, default: Any = None) -> Any:
        """Returns the value associated with key or default if not found."""
        raise NotImplementedError

    @abstractmethod
    def set_entry(self, key: Hashable, value: Any) -> None:
        """Sets the value associated with key."""
        raise NotImplementedError

    @abstractmethod
    def del_entry(self, key: Hashable) -> None:
        """Deletes the entry associated with key."""
        raise NotImplementedError

    @abstractmethod
    def _get_evictees(self, n: int) -> Iterable[Hashable]:
        """Returns a iterable of the next n keys to be evicted."""
        raise NotImplementedError


class RandomCache(AbstractCache):
    """
    Generic cache class.

    Utilizes the random eviction policy.
    """

    __slots__ = '_mapping'

    def __init__(self, size: Optional[int] = None, items: Union[Mapping[Hashable, Any], Iterable[Tuple[Hashable, Any]]] = ()) -> None:
        """Initializes a RandomCache instance."""
        super().__init__(size)

        self._mapping = dict(items)
        self.trim()

    def __len__(self) -> int:
        return len(self._mapping)

    def __iter__(self) -> Iterator[Tuple[Hashable, Any]]:
        return iter(self._mapping.items())

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self._size!r}, {dict(iter(self))!r})'

    def get_entry(self, key: Hashable, default: Any = None) -> Any:
        try:
            value = self._mapping[key]
            self._lookups += 1
            self._hits += 1
            return value

        except KeyError:
            self._lookups += 1
            return default

    def set_entry(self, key: Hashable, value: Any) -> None:
        self._mapping[key] = value
        self.trim()

    def del_entry(self, key: Hashable) -> None:
        try: del self._mapping[key]
        except KeyError: pass

    def _get_evictees(self, n: int) -> Iterable[Hashable]:
        return sample(list(self._mapping), n)


class LruCache(RandomCache):
    """
    Generic cache class.

    Utilizes the least-recently-used eviction policy.
    """

    def __init__(self, size: Optional[int] = None, items: Union[Mapping[Hashable, Any], Iterable[Tuple[Hashable, Any]]] = ()) -> None:
        """Initializes a LruCache instance."""
        super().__init__(size)

        self._mapping = OrderedDict(items)
        self.trim()

    def get_entry(self, key: Hashable, default: Any = None) -> Any:
        value = super().get_entry(key, default)

        try: self._mapping.move_to_end(key)
        except KeyError: pass

        return value

    def least_recent(self, n: Optional[int] = None) -> Iterator[Tuple[Hashable, Any]]:
        """Returns an iterator over the least-recently-used items."""
        it = iter(self._mapping.items())

        if n is not None:
            it = islice(it, clamp(0, n, len(self._mapping)))

        return it

    def most_recent(self, n: Optional[int] = None) -> Iterator[Tuple[Hashable, Any]]:
        """Returns an iterator over most-recently-used items."""
        it = reversed(self._mapping.items())

        if n is not None:
            it = islice(it, clamp(0, n, len(self._mapping)))

        return it

    def _get_evictees(self, n: int) -> Iterable[Hashable]:
        return (k for (k, _) in self.least_recent(n))


class LfuCache(RandomCache):
    """
    Generic cache class.

    Utilizes the least-frequently-used eviction policy.
    """

    __slots__ = '_counts'

    def __init__(self, size: Optional[int] = None, items: Union[Mapping[Hashable, Any], Iterable[Tuple[Hashable, Any]]] = ()) -> None:
        """Initializes a LfuCache instance."""
        if isinstance(items, Mapping):
            self._counts = dict.fromkeys(items, 0)
        elif hasattr(items, 'keys'):
            self._counts = dict.fromkeys(items.keys(), 0)
        else:
            for (key, _) in items:
                self._counts[key] = 0

        super().__init__(size, items)

    def get_entry(self, key: Hashable, default: Any = None) -> Any:
        try:
            value = self._mapping[key]
            self._counts[key] += 1
            self._lookups += 1
            self._hits += 1
            return value

        except KeyError:
            self._lookups += 1
            return default

    def set_entry(self, key: Hashable, value: Any) -> None:
        super().set_entry(key, value)

        if key not in self._counts:
            self._counts[key] = 0

    def del_entry(self, key: Hashable) -> None:
        super().del_entry(key)

        try: del self._counts[key]
        except KeyError: pass

    def least_frequent(self, n: Optional[int] = None) -> Iterator[Tuple[Hashable, Any]]:
        """Returns a iterator over the least-frequently-used items."""
        it = ((key, self._mapping[key]) for (key, _) in sorted(self._counts.items(), key=lambda item: item[1]))

        if n is not None:
            it = islice(it, clamp(0, n, len(self._mapping)))

        return it

    def most_frequent(self, n: Optional[int] = None) -> Iterator[Tuple[Hashable, Any]]:
        """Returns an iterator over the most-frequently-used items."""
        it = ((key, self._mapping[key]) for (key, _) in sorted(self._counts.items(), key=lambda item: item[1], reverse=True))

        if n is not None:
            it = islice(it, clamp(0, n, len(self._mapping)))

        return it

    def _get_evictees(self, n: int) -> Iterable[Hashable]:
        return (k for (k, _) in self.least_frequent(n))


def clamp(low: int, val: int, high: int) -> int:
    """Clamps a numeric value to a range."""
    return sorted((low, val, high))[1]
