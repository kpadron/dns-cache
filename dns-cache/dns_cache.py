import typing as _typing
import itertools as _it
import collections as _collections

class LruCache(_collections.OrderedDict):
    """
    """
    def __init__(self, size: _typing.Optional[int] = None, *args, **kwargs) -> None:
        """
        """
        super().__init__(*args, **kwargs)

        self._size = size if size is None else max(int(size), 1)

        self._lookups = 0
        self._hits = 0
        self._evictions = 0

    def __getitem__(self, key: _typing.Hashable) -> _typing.Any:
        """
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

    def __setitem__(self,  key: _typing.Hashable, value: _typing.Hashable) -> None:
        """
        """
        super().__setitem__(key, value)
        if self._size is not None:
            if len(self) > self._size:
                evictee = next(iter(self))
                del self[evictee]
                self._evictions += 1

    def get(self, key: _typing.Hashable, default: _typing.Any = None) -> _typing.Any:
        """
        """
        try:
            value = self[key]
            return value

        except KeyError:
            return default

    def least_recent(self, n: int = 1) -> _typing.Sequence:
        """
        """
        n = 0 if n <= 0 else min(n, len(self))
        return list(_it.islice(self.__iter__(), n))

    def most_recent(self, n: int = 1) -> _typing.Sequence:
        """
        """
        n = 0 if n <= 0 else min(n, len(self))
        return list(_it.islice(self.__reversed__(), n))

    @property
    def lookups(self) -> int:
        """
        """
        return self._lookups

    @property
    def hits(self) -> int:
        """
        """
        return self._hits

    @property
    def misses(self) -> int:
        """
        """
        return self._lookups - self._hits

    @property
    def evictions(self) -> int:
        """
        """
        return self._evictions

    @property
    def hit_ratio(self) -> float:
        """
        """
        try: return 1.00 * self._hits / self._lookups
        except ZeroDivisionError: return 0

    @property
    def miss_ratio(self) -> float:
        """
        """
        try: return 1.00 * self.misses / self._lookups
        except ZeroDivisionError: return 0
