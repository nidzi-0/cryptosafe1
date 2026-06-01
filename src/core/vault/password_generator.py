from __future__ import annotations

import math
import secrets
import string
from collections import deque


class PasswordGeneratorError(Exception):
    """Базовая ошибка генератора паролей."""


class PasswordStrengthError(PasswordGeneratorError):
    """Ошибка, если пароль не проходит проверку надёжности."""


class PasswordDuplicateError(PasswordGeneratorError):
    """Ошибка, если пароль повторяет один из последних сгенерированных."""


class PasswordGenerator:
    DEFAULT_LENGTH = 16
    MIN_LENGTH = 8
    MAX_LENGTH = 64

    HISTORY_LIMIT = 20
    MIN_STRENGTH_SCORE = 3
    MAX_GENERATION_ATTEMPTS = 100

    LOWERCASE = string.ascii_lowercase
    UPPERCASE = string.ascii_uppercase
    DIGITS = string.digits
    SPECIAL_CHARS = "!@#$%^&*"

    SIMILAR_CHARS = set("lI10O")

    SPECIAL = SPECIAL_CHARS

    def __init__(self):
        self._recent_passwords: deque[str] = deque(maxlen=self.HISTORY_LIMIT)

    def generate(
        self,
        length: int = DEFAULT_LENGTH,
        use_lowercase: bool = True,
        use_uppercase: bool = True,
        use_digits: bool = True,
        use_special: bool = True,
        exclude_similar: bool = False,
        min_strength_score: int = MIN_STRENGTH_SCORE,
        max_attempts: int = MAX_GENERATION_ATTEMPTS,
        **legacy_options,
    ) -> str:

        use_lowercase = legacy_options.get("use_lower", use_lowercase)
        use_uppercase = legacy_options.get("use_upper", use_uppercase)
        exclude_similar = legacy_options.get("exclude_ambiguous", exclude_similar)

        self._validate_length(length)
        self._validate_strength_score(min_strength_score)

        groups = self._build_character_groups(
            use_lowercase=use_lowercase,
            use_uppercase=use_uppercase,
            use_digits=use_digits,
            use_special=use_special,
            exclude_similar=exclude_similar,
        )

        if length < len(groups):
            raise PasswordGeneratorError(
                "Длина пароля меньше количества выбранных наборов символов."
            )

        for _ in range(max_attempts):
            password = self._generate_candidate(length, groups)

            if self.is_recent_duplicate(password):
                continue

            strength = self.analyze_strength(password)

            if strength["score"] < min_strength_score:
                continue

            self._remember_password(password)

            return password

        raise PasswordGeneratorError(
            "Не удалось сгенерировать пароль, удовлетворяющий требованиям "
            "надёжности и уникальности."
        )

    def _validate_length(self, length: int) -> None:
        if not isinstance(length, int):
            raise PasswordGeneratorError("Длина пароля должна быть целым числом.")

        if length < self.MIN_LENGTH:
            raise PasswordGeneratorError(
                f"Минимальная длина пароля: {self.MIN_LENGTH}."
            )

        if length > self.MAX_LENGTH:
            raise PasswordGeneratorError(
                f"Максимальная длина пароля: {self.MAX_LENGTH}."
            )

    def _validate_strength_score(self, score: int) -> None:
        if not isinstance(score, int):
            raise PasswordGeneratorError("Оценка надёжности должна быть целым числом.")

        if score < 0 or score > 4:
            raise PasswordGeneratorError(
                "Оценка надёжности должна быть в диапазоне от 0 до 4."
            )

    def _build_character_groups(
        self,
        use_lowercase: bool,
        use_uppercase: bool,
        use_digits: bool,
        use_special: bool,
        exclude_similar: bool,
    ) -> list[str]:
        groups = []

        if use_lowercase:
            groups.append(self.LOWERCASE)

        if use_uppercase:
            groups.append(self.UPPERCASE)

        if use_digits:
            groups.append(self.DIGITS)

        if use_special:
            groups.append(self.SPECIAL_CHARS)

        if not groups:
            raise PasswordGeneratorError(
                "Нужно выбрать хотя бы один набор символов."
            )

        if exclude_similar:
            groups = [
                "".join(ch for ch in group if ch not in self.SIMILAR_CHARS)
                for group in groups
            ]

        groups = [group for group in groups if group]

        if not groups:
            raise PasswordGeneratorError(
                "После исключения похожих символов набор символов пуст."
            )

        return groups

    def _generate_candidate(self, length: int, groups: list[str]) -> str:
        alphabet = "".join(groups)

        password_chars = []

        for group in groups:
            password_chars.append(secrets.choice(group))

        while len(password_chars) < length:
            password_chars.append(secrets.choice(alphabet))

        secrets.SystemRandom().shuffle(password_chars)

        return "".join(password_chars)

    def analyze_strength(self, password: str) -> dict[str, object]:
        if not isinstance(password, str):
            raise PasswordStrengthError("Пароль должен быть строкой.")

        feedback = []

        length = len(password)

        if length == 0:
            return {
                "score": 0,
                "entropy_bits": 0.0,
                "feedback": ["Пароль пустой."],
            }

        pool_size = self._estimate_pool_size(password)
        entropy_bits = length * math.log2(pool_size) if pool_size > 0 else 0.0

        score = 0

        if entropy_bits >= 28:
            score = 1

        if entropy_bits >= 36 and length >= 8:
            score = 2

        if entropy_bits >= 60 and length >= 12:
            score = 3

        if entropy_bits >= 80 and length >= 16:
            score = 4

        has_lower = any(ch.islower() for ch in password)
        has_upper = any(ch.isupper() for ch in password)
        has_digit = any(ch.isdigit() for ch in password)
        has_special = any(ch in self.SPECIAL_CHARS for ch in password)

        groups_count = sum([has_lower, has_upper, has_digit, has_special])

        if length < 8:
            score = min(score, 1)
            feedback.append("Пароль короче 8 символов.")

        if groups_count < 3:
            score = min(score, 2)
            feedback.append("Использовано меньше трёх типов символов.")

        if self._has_long_repetition(password):
            score = min(score, 2)
            feedback.append("В пароле есть длинные повторяющиеся фрагменты.")

        if self._looks_like_sequence(password):
            score = min(score, 2)
            feedback.append("Пароль похож на последовательность символов.")

        if password.lower() in {
            "password",
            "qwerty",
            "qwerty123",
            "admin",
            "admin123",
            "12345678",
            "11111111",
        }:
            score = 0
            feedback.append("Пароль похож на распространённый слабый пароль.")

        if score >= self.MIN_STRENGTH_SCORE and not feedback:
            feedback.append("Пароль достаточно надёжный.")

        return {
            "score": score,
            "entropy_bits": round(entropy_bits, 2),
            "feedback": feedback,
        }

    def _estimate_pool_size(self, password: str) -> int:
        pool_size = 0

        if any(ch.islower() for ch in password):
            pool_size += 26

        if any(ch.isupper() for ch in password):
            pool_size += 26

        if any(ch.isdigit() for ch in password):
            pool_size += 10

        if any(ch in self.SPECIAL_CHARS for ch in password):
            pool_size += len(self.SPECIAL_CHARS)

        other_chars = [
            ch
            for ch in password
            if not ch.islower()
            and not ch.isupper()
            and not ch.isdigit()
            and ch not in self.SPECIAL_CHARS
        ]

        if other_chars:
            pool_size += 16

        return pool_size

    def _has_long_repetition(self, password: str) -> bool:
        if len(password) < 4:
            return False

        current = password[0]
        count = 1

        for ch in password[1:]:
            if ch == current:
                count += 1

                if count >= 4:
                    return True
            else:
                current = ch
                count = 1

        return False

    def _looks_like_sequence(self, password: str) -> bool:
        lowered = password.lower()

        known_sequences = [
            "abcdefghijklmnopqrstuvwxyz",
            "0123456789",
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm",
        ]

        for sequence in known_sequences:
            for i in range(0, len(sequence) - 3):
                fragment = sequence[i : i + 4]

                if fragment in lowered:
                    return True

                if fragment[::-1] in lowered:
                    return True

        return False

    def is_recent_duplicate(self, password: str) -> bool:
        return password in self._recent_passwords

    def _remember_password(self, password: str) -> None:
        self._recent_passwords.append(password)

    def get_recent_passwords(self) -> list[str]:
        return list(self._recent_passwords)

    def clear_history(self) -> None:
        self._recent_passwords.clear()