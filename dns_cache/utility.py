import itertools as it
from collections import OrderedDict
from collections.abc import Awaitable as _Awaitable
from collections.abc import Collection as _Collection
from collections.abc import Container as _Container
from collections.abc import MutableMapping as _MutableMapping
from collections.abc import Sequence as _Sequence
from typing import (Any, Awaitable, Container, Hashable, Iterable, Iterator,
                    Mapping, Optional, Tuple, Union)

__all__ = \
[
    'ContainerView',
    'CollectionView',
    'SequenceView',
    'AwaitableView',
    'Cache',
    'LruCache',
]


class ContainerView(_Container):
    """Provides a read-only view for an arbitrary container."""
    __slots__ = '_container'

    def __init__(self, container: Container) -> None:
        self._container = container

    def __contains__(self, item) -> bool:
        return item in self._container

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self._container!r})'


class CollectionView(ContainerView, _Collection):
    """Provides a read-only view for an arbitrary collection."""
    __slots__ = ()

    def __iter__(self) -> Iterator:
        return iter(self._container)

    def __len__(self) -> int:
        return len(self._container)


class SequenceView(CollectionView, _Sequence):
    """Provides a read-only view for an arbitrary sequence."""
    __slots__ = ()

    def __getitem__(self, key: int) -> Any:
        return self._container[key]


class AwaitableView(_Awaitable):
    """Provides a read-only view for an arbitrary awaitable."""
    __slots__ = '_awaitable'

    def __init__(self, awaitable: Awaitable):
        self._awaitable = awaitable

    def __await__(self) -> Iterator:
        return self._awaitable.__await__()

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self._awaitable!r})'


class Cache(_MutableMapping):
    """Generic cache class."""
    def __init__(self, size: Optional[int] = None, items: Iterable[Tuple[Hashable, Any]] = ()) -> None:
        """
        Initializes a Cache instance.

        Args:
            size: The maximum size the cache is allowed to grow to.
                  If unspecified or None then the cache size is unbounded.
            items: A optional iterable of key, value pairs to initialize
                   the instance with.
        """
        self.size = size

        self._lookups = 0
        self._hits = 0
        self._evictions = 0

        self._mapping = {}
        for (key, value) in items:
            self.set_entry(key, value)

    def __len__(self) -> int:
        return len(self._mapping)

    def __iter__(self) -> Iterator:
        return iter(self._mapping)

    def __getitem__(self, key: Hashable) -> Any:
        try:
            value = self._mapping[key]
            self._lookups += 1
            self._hits += 1
            return value

        except KeyError:
            self._lookups += 1
            raise

    def __setitem__(self, key: Hashable, value: Any) -> None:
        self._mapping[key] = value
        self.trim()

    def __delitem__(self, key: Hashable) -> None:
        del self._mapping[key]

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self._size!r}, {list(self._mapping.items())!r})'

    def trim(self) -> None:
        """Ensures the cache is bounded by the size attribute removing entries if necessary."""
        if self._size is not None:
            while len(self._mapping) > self._size:
                self._mapping.popitem()
                self._evictions += 1

    def get_entry(self, key: Hashable, default: Optional[Any] = None) -> Any:
        """Returns the value associated with key or default if not found."""
        return self.get(key, default)

    def set_entry(self, key: Hashable, value: Any) -> None:
        """Sets the value associated with key."""
        self[key] = value

    def del_entry(self, key: Hashable) -> None:
        """Deletes the entry associated with key."""
        try: del self[key]
        except KeyError: pass

    @property
    def size(self) -> int:
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
        return 1.0 - self.hit_ratio

    @property
    def stats(self) -> Mapping[str, Union[None, int, float]]:
        """Returns a mapping of current cache statistics."""
        keys = ('size', 'lookups', 'hits', 'misses', 'evictions', 'hit_ratio', 'miss_ratio')
        mapping = {'len': len(self)}
        mapping.update((key, getattr(self, key)) for key in keys)
        return mapping


class LruCache(Cache):
    """Cache utilizing the least-recently-used eviction policy."""
    def __init__(self, size: Optional[int] = None, items: Iterable[Tuple[Hashable, Any]] = ()) -> None:
        """
        Initializes a LruCache instance.

        Args:
            size: The maximum size the cache is allowed to grow to.
                  If unspecified or None then the cache size is unbounded.
            items: A optional iterable of key, value pairs to initialize
                   the instance with.
        """
        super().__init__(size)

        self._mapping = OrderedDict()
        for (key, value) in items:
            self.set_entry(key, value)

    def get_entry(self, key: Hashable, default: Optional[Any] = None) -> Any:
        value = super().get_entry(key, default)

        try: self._mapping.move_to_end(key, False)
        except KeyError: pass

        return value

    def set_entry(self, key: Hashable, value: Any) -> None:
        self._mapping[key] = value
        self._mapping.move_to_end(key, False)
        self.trim()

    def least_recent(self, n: int = 1) -> Iterator:
        """Returns an iterator of the n least-recently-used items."""
        n = 0 if n <= 0 else min(n, len(self))
        return it.islice(reversed(self._mapping.items()), n)

    def most_recent(self, n: int = 1) -> Iterator:
        """Returns an iterator over the n most-recently-used items."""
        n = 0 if n <= 0 else min(n, len(self))
        return it.islice(iter(self._mapping.items()), n)
