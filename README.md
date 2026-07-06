# Цифровая подстанция 

Учебный стенд для моделирования цифровой подстанции для защиты и атаки.

## Возможности

- эмуляция нескольких устройств РЗА;
- обмен GOOSE-пакетами;
- агрегирование данных МОД;
- обнаружение аномалий;
- автоматическое реагирование на атаки;
- моделирование различных сценариев.

---

## Структура проекта

```
.
├── base version/
│   ├── src/
│   │   ├── mod_emulator.py
│   │   ├── rza_emulator.py
│   │   ├── goose_gen.py
│   │   ├── matrix_and_scenarios.py
│   │   ├── predict.py
│   │    └── ...
│   │
│   ├── conf/
│   │   ├── conf_mod.yaml
│   │   ├── conf_rza1.yaml
│   │   ├── conf_rza2.yaml
│   │    └── ...
│   │
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── requirements.txt
│
├── modified version\
│   ├── src/
│   │   ├──attack_DoS.py
│   │   ├──attack_evasion.py
│   │   ├──attack_masquerade.py
│   │   ├──attack_silence.py
│   │   ├──attack_stnum.py
│   │   ├── mod_emulator.py
│   │   ├── rza_emulator.py
│   │   ├── goose_gen.py
│   │   ├── matrix_and_scenarios.py
│   │   ├── predict.py
│   │    └── ...
│   │
│   ├── conf/
│   │   ├── conf_mod.yaml
│   │   ├── conf_rza1.yaml
│   │   ├── conf_rza2.yaml
│   │    └── ...
│   │
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── requirements.txt
│
│
└── README.md

```

---

## Требования

Docker
Docker Compose

---

## Запуск

```
docker compose up --build
```

---

## Остановка

```
docker compose down
```


---

## Просмотр логов

```
docker compose logs -f
```

---

# Конфигурация устройств

Каждое устройство имеет собственный YAML-файл.

Например:

```
conf_rza1.yaml
```

Изменяются:

- MAC-адрес
- goCBRef
- datSet
- goID
- номер устройства

---

## Добавление нового РЗА

Создать

```
conf_rzaX.yaml
```

Добавить сервис в

```
docker-compose.yml
```

Добавить GOOSEControlBlockX в

```
conf_mod.yaml
```

---

# Контроль и защита

Основная логика находится в

```
src/mod_emulator.py
```

---

## Моделирование атак

Можно:

- изменить goCBRef;
- изменить MAC-адрес;
- остановить контейнер;
- отправить ложный GOOSE.
- и т.д


В нашем случае было реализованы:

- Сценарий 1: Атака "Обход детектора" (Data Evasion)
- Сценарий 2: Атака "Подмена источника" (Masquerade / Spoofing)
- Сценарий 2: Атака "Подмена источника" (Masquerade / Spoofing)
- Сценарий 4: Атака "Тишина в эфире" (Silence / DoS via Heartbeat)
- Сценарий 5: DoS Атака

Для их заупска необходимо вместо заупска эмулятора rza в docker_compose, запустить атаку.
---

## Авторы
Owliloop
Шнырь
Сон Гоку
...
