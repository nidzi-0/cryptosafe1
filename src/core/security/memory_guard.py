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