from __future__ import annotations

import secrets
import string
from collections import deque


class PasswordGenerator:
    UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    LOWER = "abcdefghijklmnopqrstuvwxyz"
    DIGITS = "0123456789"
    SPECIAL = "!@#$%^&*"
    AMBIGUOUS = set("lI10O")

    def __init__(self) -> None:
        self.history = deque(maxlen=20)

    def generate(
        self,
        length: int = 16,
        use_upper: bool = True,
        use_lower: bool = True,
        use_digits: bool = True,
        use_special: bool = True,
        exclude_ambiguous: bool = False,
    ) -> str:
        if length < 8 or length > 64:
            raise ValueError("Длина пароля должна быть от 8 до 64 символов")

        sets = []

        if use_upper:
            sets.append(self._filter(self.UPPER, exclude_ambiguous))
        if use_lower:
            sets.append(self._filter(self.LOWER, exclude_ambiguous))
        if use_digits:
            sets.append(self._filter(self.DIGITS, exclude_ambiguous))
        if use_special:
            sets.append(self._filter(self.SPECIAL, exclude_ambiguous))

        if not sets:
            raise ValueError("Должен быть выбран хотя бы один набор символов")

        if length < len(sets):
            raise ValueError("Длина слишком мала для выбранных наборов")

        for _ in range(100):
            password_chars = [secrets.choice(charset) for charset in sets]

            all_chars = "".join(sets)

            while len(password_chars) < length:
                password_chars.append(secrets.choice(all_chars))

            self._secure_shuffle(password_chars)

            password = "".join(password_chars)

            if password not in self.history:
                self.history.append(password)
                return password

        raise ValueError("Не удалось сгенерировать уникальный пароль")

    def _filter(self, charset: str, exclude_ambiguous: bool) -> str:
        if not exclude_ambiguous:
            return charset

        return "".join(ch for ch in charset if ch not in self.AMBIGUOUS)

    def _secure_shuffle(self, chars: list[str]) -> None:
        for i in range(len(chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            chars[i], chars[j] = chars[j], chars[i]