# CryptoSafe Manager

CryptoSafe Manager — локальный менеджер паролей на Python.

Приложение предназначено для безопасного хранения учётных данных в локальной базе данных с использованием шифрования, мастер-пароля, защищённого буфера обмена, журнала аудита, импорта/экспорта и дополнительных механизмов security hardening.

## Project overview

Основная цель проекта — создать локальный password manager, который:

- хранит пароли в зашифрованном виде;
- не передаёт данные на внешние серверы;
- использует мастер-пароль;
- поддерживает добавление, редактирование, удаление и поиск записей;
- поддерживает secure clipboard;
- ведёт audit log;
- поддерживает import/export;
- имеет panic mode и auto-lock.

## Technologies

- Python
- Tkinter
- SQLite
- AES-256-GCM
- Argon2
- PBKDF2-HMAC-SHA256
- pytest
- pytest-cov
- PyInstaller

## Installation

```powershell
git clone https://github.com/nidzi-0/cryptosafe1.git
cd cryptosafe1
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt