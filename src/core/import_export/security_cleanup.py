from typing import Any


class SensitiveDataCleaner:
    @staticmethod
    def clear_bytearray(value: bytearray) -> None:
        try:
            for i in range(len(value)):
                value[i] = 0
        except Exception:
            pass

    @staticmethod
    def clear_memoryview(value: memoryview) -> None:
        try:
            if not value.readonly:
                value[:] = b"\x00" * len(value)
        except Exception:
            pass

    @staticmethod
    def clear(value: Any) -> None:
        try:
            if isinstance(value, bytearray):
                SensitiveDataCleaner.clear_bytearray(value)
                return

            if isinstance(value, memoryview):
                SensitiveDataCleaner.clear_memoryview(value)
                return

            if isinstance(value, list):
                for item in value:
                    SensitiveDataCleaner.clear(item)
                value.clear()
                return

            if isinstance(value, dict):
                for key in list(value.keys()):
                    SensitiveDataCleaner.clear(value[key])
                value.clear()
                return

        except Exception:
            pass

    @staticmethod
    def clear_many(*values: Any) -> None:
        for value in values:
            SensitiveDataCleaner.clear(value)