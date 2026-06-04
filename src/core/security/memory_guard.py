from __future__ import annotations

import ctypes
import os
import platform
from dataclasses import dataclass


class MemoryGuardError(Exception):
    """Базовая ошибка"""


@dataclass
class SecureBufferInfo:
    size: int
    locked: bool
    platform_name: str


class SecureMemory:

    def __init__(self):
        self.system = platform.system()
        self._libc = None
        self._kernel32 = None

        if self.system == "Windows":
            try:
                self._kernel32 = ctypes.windll.kernel32
            except Exception:
                self._kernel32 = None
        else:
            try:
                self._libc = ctypes.CDLL(None)
            except Exception:
                self._libc = None

    def allocate(self, size: int) -> ctypes.Array:
        if size <= 0:
            raise ValueError("size must be positive")

        return (ctypes.c_ubyte * size)()

    def lock(self, buffer: ctypes.Array, size: int) -> bool:
        try:
            address = ctypes.addressof(buffer)

            if self.system == "Windows" and self._kernel32 is not None:
                return bool(self._kernel32.VirtualLock(ctypes.c_void_p(address), ctypes.c_size_t(size)))

            if self._libc is not None and hasattr(self._libc, "mlock"):
                return self._libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(size)) == 0

        except Exception:
            return False

        return False

    def unlock(self, buffer: ctypes.Array, size: int) -> bool:
        try:
            address = ctypes.addressof(buffer)

            if self.system == "Windows" and self._kernel32 is not None:
                return bool(self._kernel32.VirtualUnlock(ctypes.c_void_p(address), ctypes.c_size_t(size)))

            if self._libc is not None and hasattr(self._libc, "munlock"):
                return self._libc.munlock(ctypes.c_void_p(address), ctypes.c_size_t(size)) == 0

        except Exception:
            return False

        return False

    def secure_zero(self, buffer: ctypes.Array, size: int) -> None:
        if size <= 0:
            return

        address = ctypes.addressof(buffer)

        try:
            if self.system == "Windows" and self._kernel32 is not None and hasattr(self._kernel32, "RtlSecureZeroMemory"):
                self._kernel32.RtlSecureZeroMemory(ctypes.c_void_p(address), ctypes.c_size_t(size))
            else:
                ctypes.memset(ctypes.c_void_p(address), 0, ctypes.c_size_t(size))
        finally:
            # second pass to avoid relying on one platform function only
            ctypes.memset(ctypes.c_void_p(address), 0, ctypes.c_size_t(size))

    def wipe_bytearray(self, data: bytearray) -> None:
        for index in range(len(data)):
            data[index] = 0

    def wipe_bytes_copy(self, data: bytes) -> bytearray:
        mutable = bytearray(data)
        self.wipe_bytearray(mutable)
        return mutable


class SecretHolder:

    def __init__(self, data: bytes):
        if not isinstance(data, bytes):
            raise TypeError("SecretHolder requires bytes")

        self._memory = SecureMemory()
        self._size = len(data)
        self._buffer = self._memory.allocate(max(self._size, 1))
        self._closed = False

        if self._size:
            ctypes.memmove(self._buffer, data, self._size)

        self._locked = self._memory.lock(self._buffer, max(self._size, 1))

    @property
    def info(self) -> SecureBufferInfo:
        return SecureBufferInfo(
            size=self._size,
            locked=self._locked,
            platform_name=platform.system(),
        )

    def get_bytes(self) -> bytes:
        if self._closed:
            raise MemoryGuardError("SecretHolder is already closed")

        return bytes(self._buffer[: self._size])

    def close(self) -> None:
        if self._closed:
            return

        self._memory.secure_zero(self._buffer, max(self._size, 1))
        self._memory.unlock(self._buffer, max(self._size, 1))
        self._closed = True

    def __enter__(self) -> "SecretHolder":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


class MemoryDumpScanner:

    @staticmethod
    def contains_plaintext(memory_blocks: list[bytes], plaintext: bytes) -> bool:
        return any(plaintext in block for block in memory_blocks)

    @staticmethod
    def process_dump_available() -> bool:
        return os.name in {"nt", "posix"}
class CanaryCorruptionError(MemoryGuardError):
    """Raised when secure heap guard/canary values are corrupted."""


class SecureHeapBlock:
    GUARD_SIZE = 32
    CANARY_SIZE = 16

    def __init__(self, payload_size: int):
        if payload_size <= 0:
            raise ValueError("payload_size must be positive")

        self.memory = SecureMemory()
        self.payload_size = payload_size
        self.total_size = (
            self.GUARD_SIZE
            + self.CANARY_SIZE
            + self.payload_size
            + self.CANARY_SIZE
            + self.GUARD_SIZE
        )

        self._buffer = self.memory.allocate(self.total_size)
        self._closed = False
        self._locked = self.memory.lock(self._buffer, self.total_size)

        import secrets

        self._left_canary = secrets.token_bytes(self.CANARY_SIZE)
        self._right_canary = secrets.token_bytes(self.CANARY_SIZE)

        self._init_guards()
        self._write_canaries()

    @property
    def payload_offset(self) -> int:
        return self.GUARD_SIZE + self.CANARY_SIZE

    @property
    def left_canary_offset(self) -> int:
        return self.GUARD_SIZE

    @property
    def right_canary_offset(self) -> int:
        return self.GUARD_SIZE + self.CANARY_SIZE + self.payload_size

    def _init_guards(self) -> None:
        for i in range(self.GUARD_SIZE):
            self._buffer[i] = 0xAA

        right_guard_start = self.right_canary_offset + self.CANARY_SIZE

        for i in range(right_guard_start, self.total_size):
            self._buffer[i] = 0xBB

    def _write_canaries(self) -> None:
        for i, byte in enumerate(self._left_canary):
            self._buffer[self.left_canary_offset + i] = byte

        for i, byte in enumerate(self._right_canary):
            self._buffer[self.right_canary_offset + i] = byte

    def _read_region(self, offset: int, size: int) -> bytes:
        return bytes(self._buffer[offset: offset + size])

    def verify_canaries(self) -> bool:
        if self._closed:
            return False

        left = self._read_region(self.left_canary_offset, self.CANARY_SIZE)
        right = self._read_region(self.right_canary_offset, self.CANARY_SIZE)

        return left == self._left_canary and right == self._right_canary

    def verify_guards(self) -> bool:
        if self._closed:
            return False

        left_guard = bytes(self._buffer[0:self.GUARD_SIZE])
        right_guard_start = self.right_canary_offset + self.CANARY_SIZE
        right_guard = bytes(self._buffer[right_guard_start:self.total_size])

        return (
            left_guard == bytes([0xAA]) * self.GUARD_SIZE
            and right_guard == bytes([0xBB]) * self.GUARD_SIZE
        )

    def _ensure_valid(self) -> None:
        if self._closed:
            raise MemoryGuardError("SecureHeapBlock is already closed")

        if not self.verify_canaries() or not self.verify_guards():
            self.close()
            raise CanaryCorruptionError(
                "Secure heap block guard/canary corruption detected"
            )

    def write(self, data: bytes) -> None:
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")

        if len(data) > self.payload_size:
            raise ValueError("data is larger than payload")

        self._ensure_valid()

        start = self.payload_offset

        for i in range(self.payload_size):
            self._buffer[start + i] = 0

        for i, byte in enumerate(data):
            self._buffer[start + i] = byte

        self._ensure_valid()

    def read(self) -> bytes:
        self._ensure_valid()
        raw = self._read_region(self.payload_offset, self.payload_size)
        return raw.rstrip(b"\x00")

    def close(self) -> None:
        if self._closed:
            return

        try:
            self.memory.secure_zero(self._buffer, self.total_size)
        except TypeError:
            self.memory.secure_zero(self._buffer, self.total_size)

        self.memory.unlock(self._buffer, self.total_size)
        self._closed = True

    @property
    def info(self):
        return {
            "payload_size": self.payload_size,
            "total_size": self.total_size,
            "locked": self._locked,
            "canary_valid": self.verify_canaries() if not self._closed else False,
            "closed": self._closed,
        }

    def corrupt_left_canary_for_testing(self) -> None:
        self._buffer[self.left_canary_offset] ^= 0xFF

    def corrupt_right_guard_for_testing(self) -> None:
        self._buffer[self.total_size - 1] ^= 0xFF


class SecureHeapAllocator:

    def __init__(self):
        self._blocks = []

    def allocate(self, payload_size: int) -> SecureHeapBlock:
        block = SecureHeapBlock(payload_size)
        self._blocks.append(block)
        return block

    def allocate_with_data(self, data: bytes) -> SecureHeapBlock:
        block = self.allocate(max(len(data), 1))
        block.write(data)
        return block

    def free(self, block: SecureHeapBlock) -> None:
        block.close()

        if block in self._blocks:
            self._blocks.remove(block)

    def free_all(self) -> None:
        for block in list(self._blocks):
            block.close()

        self._blocks.clear()

    def active_blocks(self) -> int:
        return sum(1 for block in self._blocks if not block.info["closed"])


class StackSecret:

    def __init__(self, data: bytes):
        if not isinstance(data, bytes):
            raise TypeError("StackSecret requires bytes")

        self._memory = SecureMemory()
        self._data = bytearray(data)
        self._closed = False

    def bytes(self) -> bytes:
        if self._closed:
            raise MemoryGuardError("StackSecret is already closed")

        return bytes(self._data)

    def close(self) -> None:
        if self._closed:
            return

        if hasattr(self._memory, "wipe_bytearray"):
            self._memory.wipe_bytearray(self._data)
        else:
            for i in range(len(self._data)):
                self._data[i] = 0

        self._closed = True

    def __enter__(self) -> "StackSecret":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
class MMapLockedBuffer:
    def __init__(self, size: int):
        if size <= 0:
            raise ValueError("size must be positive")

        self.size = size
        self.closed = False
        self.locked = False
        self._mmap = None
        self._fallback_buffer = None
        self._memory = SecureMemory()

        try:
            import mmap

            flags = getattr(mmap, "MAP_PRIVATE", 0)
            flags |= getattr(mmap, "MAP_ANONYMOUS", getattr(mmap, "MAP_ANON", 0))

            if hasattr(mmap, "MAP_LOCKED"):
                flags |= mmap.MAP_LOCKED

            self._mmap = mmap.mmap(
                -1,
                self.size,
                flags=flags,
                prot=mmap.PROT_READ | mmap.PROT_WRITE,
            )
            self.locked = hasattr(mmap, "MAP_LOCKED")
        except Exception:
            self._fallback_buffer = self._memory.allocate(self.size)
            self.locked = self._memory.lock(self._fallback_buffer, self.size)

    def write(self, data: bytes) -> None:
        if self.closed:
            raise MemoryGuardError("MMapLockedBuffer is already closed")

        if len(data) > self.size:
            raise ValueError("data is larger than buffer")

        if self._mmap is not None:
            self._mmap.seek(0)
            self._mmap.write(b"\x00" * self.size)
            self._mmap.seek(0)
            self._mmap.write(data)
            return

        for index in range(self.size):
            self._fallback_buffer[index] = 0

        for index, byte in enumerate(data):
            self._fallback_buffer[index] = byte

    def read(self) -> bytes:
        if self.closed:
            raise MemoryGuardError("MMapLockedBuffer is already closed")

        if self._mmap is not None:
            self._mmap.seek(0)
            return self._mmap.read(self.size).rstrip(b"\x00")

        return bytes(self._fallback_buffer[: self.size]).rstrip(b"\x00")

    def close(self) -> None:
        if self.closed:
            return

        if self._mmap is not None:
            self._mmap.seek(0)
            self._mmap.write(b"\x00" * self.size)
            self._mmap.close()
        elif self._fallback_buffer is not None:
            self._memory.secure_zero(self._fallback_buffer, self.size)
            self._memory.unlock(self._fallback_buffer, self.size)

        self.closed = True

    def __enter__(self) -> "MMapLockedBuffer":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class VolatileSecret:

    def __init__(self, data: bytes):
        if not isinstance(data, bytes):
            raise TypeError("VolatileSecret requires bytes")

        self._memory = SecureMemory()
        self._data = bytearray(data)
        self._closed = False

    def reveal(self) -> bytes:
        if self._closed:
            raise MemoryGuardError("VolatileSecret is already closed")

        return bytes(self._data)

    def wipe(self) -> None:
        if self._closed:
            return

        if hasattr(self._memory, "wipe_bytearray"):
            self._memory.wipe_bytearray(self._data)
        else:
            for index in range(len(self._data)):
                self._data[index] = 0

        self._closed = True

    def __enter__(self) -> "VolatileSecret":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.wipe()