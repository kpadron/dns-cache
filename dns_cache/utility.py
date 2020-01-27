from collections.abc import Awaitable as _Awaitable
from collections.abc import Collection as _Collection
from collections.abc import Container as _Container
from collections.abc import Sequence as _Sequence
from typing import (Any, Awaitable, Container, Iterator)

__all__ = \
[
    'ContainerView',
    'CollectionView',
    'SequenceView',
    'AwaitableView',
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
