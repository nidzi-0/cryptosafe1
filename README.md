# CryptoSafe Manager

CryptoSafe Manager — локальный менеджер паролей на Python, разработанный в рамках курса по прикладной криптографии.

Проект реализует защищённое хранение учётных данных, мастер-пароль, шифрование записей, безопасный буфер обмена, аудит событий, импорт/экспорт, безопасный обмен данными и дополнительные механизмы security hardening.

---

## Возможности проекта

CryptoSafe Manager поддерживает:

* создание локального защищённого хранилища;
* вход по мастер-паролю;
* добавление, редактирование, удаление и поиск записей;
* генерацию надёжных паролей;
* шифрование записей перед сохранением в базу данных;
* безопасный буфер обмена с автоочисткой;
* журнал аудита событий безопасности;
* импорт и экспорт данных;
* encrypted JSON export;
* CSV import/export;
* импорт из Bitwarden и LastPass;
* secure sharing;
* QR/key exchange;
* auto-lock при неактивности;
* panic mode;
* session recovery после блокировки;
* security profiles;
* platform security reports;
* финальные тесты и подготовку к сборке приложения.

---

## Технологии

В проекте используются:

* Python;
* Tkinter;
* SQLite;
* AES-256-GCM;
* Argon2;
* PBKDF2-HMAC-SHA256;
* HMAC / hash chain для аудита;
* pytest;
* pytest-cov;
* PyInstaller.

---

## Криптографическая логика

Основная криптографическая схема:

```text
Мастер-пароль пользователя
        ↓
Argon2 / PBKDF2
        ↓
Ключевой материал
        ↓
AES-256-GCM
        ↓
Зашифрованные записи в SQLite
```

В проекте используются следующие принципы:

* мастер-пароль не хранится в открытом виде;
* для шифрования записей используется AES-256-GCM;
* для каждой операции шифрования используется уникальный nonce;
* проверка пароля выполняется безопасным способом;
* для чувствительных сравнений используются constant-time операции;
* аудит защищается механизмами целостности;
* ключи разных назначений разделяются логически.

---

## Структура проекта

```text
cryptosafe1/
├── src/
│   ├── core/
│   │   ├── audit/
│   │   ├── clipboard/
│   │   ├── crypto/
│   │   ├── import_export/
│   │   ├── security/
│   │   └── vault/
│   ├── database/
│   ├── gui/
│   └── main.py
│
├── tests/
│   ├── test_sprint3_*.py
│   ├── test_sprint4_*.py
│   ├── test_sprint5_*.py
│   ├── test_sprint6_*.py
│   ├── test_sprint7_*.py
│   └── test_sprint8_*.py
│
├── docs/
│   ├── user_guide.md
│   └── technical.md
│
├── scripts/
│   ├── build_exe.ps1
│   └── run_tests_with_report.ps1
│
├── run.py
├── requirements.txt
├── pytest.ini
└── README.md
```

---

## Основные модули

### `src/core/crypto`

Модуль криптографической логики.

Отвечает за:

* проверку мастер-пароля;
* получение ключевого материала;
* совместимость с ранними спринтами;
* безопасные сравнения;
* работу с authentication/key-store логикой.

### `src/core/vault`

Модуль хранилища паролей.

Отвечает за:

* создание записей;
* получение записей;
* обновление записей;
* удаление записей;
* шифрование и расшифрование данных;
* генерацию паролей.

### `src/core/clipboard`

Модуль защищённого буфера обмена.

Отвечает за:

* копирование паролей;
* автоочистку;
* ручную очистку;
* предупреждения;
* ephemeral mode;
* platform adapter;
* защиту от использования clipboard при заблокированном хранилище.

### `src/core/audit`

Модуль журнала аудита.

Отвечает за:

* запись событий безопасности;
* hash chain;
* подпись/проверку логов;
* экспорт аудита;
* ротацию логов;
* проверку целостности.

### `src/core/import_export`

Модуль импорта, экспорта и sharing.

Отвечает за:

* encrypted JSON export;
* CSV import/export;
* Bitwarden import;
* LastPass import;
* secure sharing;
* QR/key exchange;
* проверку входных файлов;
* защиту от повреждённых и вредоносных данных.

### `src/core/security`

Модуль security hardening.

Отвечает за:

* side-channel protection;
* secure memory management;
* auto-lock;
* panic mode;
* tray/background service;
* session recovery;
* screen-lock detection;
* platform security policy;
* UX validation;
* settings validation.

---

## Установка

Клонировать репозиторий:

```powershell
git clone https://github.com/nidzi-0/cryptosafe1.git
cd cryptosafe1
```

Создать и активировать виртуальное окружение:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

Установить зависимости:

```powershell
pip install -r requirements.txt
```

---

## Запуск из исходного кода

Основной способ запуска:

```powershell
python run.py
```

Альтернативный способ:

```powershell
python -m src.main
```

---

## Запуск тестов

Запуск всех тестов:

```powershell
python -m pytest tests -v
```

Запуск тестов конкретного спринта:

```powershell
python -m pytest tests -k sprint7 -v
```

Запуск финальных тестов Sprint 8:

```powershell
python -m pytest tests -k sprint8 -v
```

---

## Отчёт покрытия

Для генерации coverage-отчёта:

```powershell
mkdir tests\report -Force
python -m pytest tests --cov=src --cov-report=term --cov-report=html:tests/report/html --junitxml=tests/report/junit.xml -v
```

После выполнения отчёт будет находиться в папке:

```text
tests/report/
```

HTML-отчёт покрытия:

```text
tests/report/html/index.html
```

JUnit-отчёт:

```text
tests/report/junit.xml
```

Также можно использовать скрипт:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_tests_with_report.ps1
```

---

## Сборка исполняемого файла

Для сборки используется PyInstaller.

Команда ручной сборки:

```powershell
pyinstaller --noconfirm --onedir --windowed --name CryptoSafeManager run.py
```

Или через готовый скрипт:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1
```

Результат сборки появится в папке:

```text
dist/CryptoSafeManager/
```

Для запуска собранного приложения открыть:

```text
dist/CryptoSafeManager/
```

и запустить:

```text
CryptoSafeManager.exe
```

---

## Основные функции

### Хранилище записей

Пользователь может:

* добавлять записи;
* редактировать записи;
* удалять записи;
* искать записи;
* хранить логины, пароли, ссылки, заметки и теги.

### Генератор паролей

Генератор поддерживает:

* настройку длины;
* заглавные буквы;
* строчные буквы;
* цифры;
* специальные символы;
* исключение похожих символов;
* оценку стойкости пароля.

### Защищённый буфер обмена

Clipboard-модуль поддерживает:

* копирование пароля;
* копирование логина;
* автоочистку;
* ручную очистку;
* предупреждение перед очисткой;
* ephemeral mode;
* очистку при panic mode.

### Импорт и экспорт

Поддерживаются:

* encrypted JSON;
* plain CSV для миграции;
* Bitwarden JSON;
* LastPass CSV;
* dry-run import;
* merge mode;
* replace mode;
* export selected entries;
* export without notes.

### Журнал аудита

Audit log фиксирует:

* успешные и неуспешные входы;
* создание записей;
* изменение записей;
* удаление записей;
* операции clipboard;
* импорт;
* экспорт;
* sharing;
* auto-lock;
* panic mode.

### Panic mode

Panic mode активируется через:

```text
Ctrl+Shift+Esc
```

При активации выполняется:

* блокировка хранилища;
* очистка буфера обмена;
* очистка чувствительных данных;
* закрытие чувствительных окон;
* запись события в audit log;
* восстановление только после повторной проверки мастер-пароля.

### Auto-lock

Auto-lock отслеживает:

* действия мыши;
* ввод с клавиатуры;
* изменение фокуса окна;
* события блокировки экрана.

После периода неактивности хранилище блокируется.

### Security profiles

Реализованы профили:

* Standard;
* Enhanced;
* Paranoid.

Профили изменяют параметры безопасности, например время auto-lock, поведение clipboard и tray/background-режима.

---

## Документация

Дополнительные документы:

* `docs/user_guide.md` — руководство пользователя;
* `docs/technical.md` — техническое описание проекта.

---

## Известные ограничения

* Низкоуровневое управление памятью в Python ограничено.
* Полная очистка всех копий чувствительных данных в памяти не может быть гарантирована средствами Python.
* Реальное поведение system tray зависит от операционной системы.
* Windows Hello, macOS Keychain и Linux keyring требуют отдельной platform-specific интеграции.
* Hardware-level защита является platform-dependent.
* Сборка PyInstaller создаётся под текущую ОС разработчика.
* Открытый CSV-экспорт следует использовать только для миграции.

---

## Будущие улучшения

Возможные направления развития:

* browser extension;
* TOTP support;
* encrypted cloud sync;
* mobile companion application;
* расширенная интеграция с Windows Hello / macOS Keychain / Linux keyring;
* улучшенный backup/restore;
* более развитый UI для audit log;
* автоматическая проверка силы всех сохранённых паролей.

---

## Проверка перед сдачей

Рекомендуемый набор команд:

```powershell
python -m pytest tests -k sprint8 -v
python -m pytest tests -k sprint7 -v
python -m pytest tests --cov=src --cov-report=term --cov-report=html:tests/report/html -v
```

Сборка:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1
```

---

## Репозиторий

```text
https://github.com/nidzi-0/cryptosafe1
```
