from __future__ import annotations

import secrets
import string


class PasswordGeneratorError(Exception):
    """Базовая ошибка генератора паролей."""


class PasswordGenerator:
    DEFAULT_LENGTH = 16
    MIN_LENGTH = 8
    MAX_LENGTH = 64

    LOWERCASE = string.ascii_lowercase
    UPPERCASE = string.ascii_uppercase
    DIGITS = string.digits
    SPECIAL_CHARS = "!@#$%^&*"

    SIMILAR_CHARS = set("lI10O")

    def generate(
        self,
        length: int = DEFAULT_LENGTH,
        use_lowercase: bool = True,
        use_uppercase: bool = True,
        use_digits: bool = True,
        use_special: bool = True,
        exclude_similar: bool = False,
    ) -> str:
        if length < self.MIN_LENGTH:
            raise PasswordGeneratorError(
                f"Минимальная длина пароля: {self.MIN_LENGTH}."
            )

        if length > self.MAX_LENGTH:
            raise PasswordGeneratorError(
                f"Максимальная длина пароля: {self.MAX_LENGTH}."
            )

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

        alphabet = "".join(groups)

        if not alphabet:
            raise PasswordGeneratorError(
                "После исключения похожих символов набор символов пуст."
            )

        password_chars = []

        for group in groups:
            if group:
                password_chars.append(secrets.choice(group))

        while len(password_chars) < length:
            password_chars.append(secrets.choice(alphabet))

        secrets.SystemRandom().shuffle(password_chars)

        return "".join(password_chars)