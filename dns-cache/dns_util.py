import asyncio as _aio
import collections as _collections
import collections.abc as _collections_abc
import struct as _struct
import typing as _typing


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
        return _struct.unpack('!H', memoryview(data)[offset:offset+2])[0]
    except _struct.error:
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
    memoryview(data)[offset:offset+2] = _struct.pack('!H', int(value) & 0xffff)

async def full_cancel(future: _aio.Future) -> None:
    """Fully cancels a future by cancelling then awaiting it.
    """
    if future.cancel():
        try: await future
        except _aio.CancelledError: pass

async def cancel_all(futures: _typing.Iterable[_aio.Future]) -> None:
    """Fully cancels all futures in a iterable of futures.
    """
    cancelled = []

    for future in futures:
        if future.cancel():
            cancelled.append(future)

    for future in cancelled:
        try: await future
        except _aio.CancelledError: pass

async def wait_first(futures: _typing.Iterable[_aio.Future], cancel_pending: bool = True) -> _aio.Future:
    """Waits for the first future in futures to complete and returns it.

    Args:
        futures: The iterable of futures to wait on.
        cancel_pending: Whether to cancel the pending futures after waiting.

    Returns:
        The first future to complete.
    """
    # Wait for the first future to complete
    (done, pending) = await _aio.wait(futures, return_when=_aio.FIRST_COMPLETED)

    # Cancel the unfinished futures
    if cancel_pending:
        await cancel_all(pending)

    # Return the first future that finished
    return done.pop()

class ContainerView(_collections_abc.Container):
    """Provides a read-only view for an arbitrary container.
    """
    __slots__ = '_container'

    def __init__(self, container: _typing.Container) -> None:
        self._container = container

    def __contains__(self, x) -> bool:
        return x in self._container

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({self._container!r})'

class CollectionView(ContainerView, _collections_abc.Collection):
    """Provides a read-only view for an arbitrary collection.
    """
    __slots__ = ()

    def __iter__(self) -> _typing.Iterator:
        return iter(self._container)

    def __len__(self) -> int:
        return len(self._container)

class SequenceView(CollectionView, _collections_abc.Sequence):
    """Provides a read-only view for an arbitrary sequence.
    """
    __slots__ = ()

    def __getitem__(self, index) -> _typing.Any:
        return self._container[index]

    def __reversed__(self) -> _typing.Iterator:
        return reversed(self._container)

class StateEvent(_aio.Event):
    """Extends asyncio.Event to provide:
        - async def wait_true()
        - async def wait_false()
    """
    def __init__(self) -> None:
        super().__init__()
        self.__ievent = _aio.Event()
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
