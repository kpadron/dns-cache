import asyncio as aio
import struct
from typing import ByteString, Iterable, Union

BytesLike = Union[ByteString, memoryview]

def isbyteslike(obj) -> bool:
    """Returns true if object provides a bytes-like interface.
    """
    return isinstance(obj, (ByteString, memoryview))

def get_short(data: BytesLike, offset: int = 0) -> int:
    """Returns a short (16-bit unsigned integer) by reading 2-bytes of data.

    Note: The short is expected to be stored in NBO when reading data.

    Args:
        data: The bytes-like object to read (must be at least 2-bytes long starting at offset).
        offset: The byte offset to start the 2-byte read.

    Raises:
        ValueError: When given invalid input data.
    """
    try: return struct.unpack('!H', memoryview(data)[offset:offset+2])[0]
    except struct.error:
        raise ValueError('data - must be at least 2-bytes long starting at offset')

def set_short(short: int, data: BytesLike, offset: int = 0) -> None:
    """Writes a short (16-bit unsigned integer) by writing 2-bytes at offset in data.

    Note: The short is stored in NBO when writing data.

    Args:
        short: The short integer value to write.
        data: The mutable bytes-like object to write to (must be at least 2-bytes long starting at offset).
        offset: The byte offset to start the 2-byte write.
    """
    memoryview(data)[offset:offset+2] = struct.pack('!H', int(short) & 0xffff)

async def full_cancel(fut: aio.Future) -> None:
    """Fully cancels a future by cancelling then awaiting it.
    """
    fut.cancel()
    try: await fut
    except aio.CancelledError: pass

async def wait_first(futs: Iterable[aio.Future], cancel_pending: bool = True) -> aio.Future:
    """Waits for the first future to complete and returns it.

    Args:
        futs: The iterable of futures to wait for.
        cancel_pending: A boolean value indicating whether to cancel the pending futures.

    Returns:
        The first future to complete.
    """
    # Wait for the first future to complete
    done, pending = await aio.wait(futs, return_when=aio.FIRST_COMPLETED)

    # Cancel the unfinished futures
    if cancel_pending:
        for fut in pending:
            fut.cancel()

    # Return the first future that finished
    return done.pop()


class StateEvent(aio.Event):
    """Extends asyncio.Event to provide:
        - async def wait_true()
        - async def wait_false()
    """
    def __init__(self) -> None:
        super().__init__()
        self.__ievent = aio.Event()
        self.__ievent.set()

    wait_true = aio.Event.wait

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
