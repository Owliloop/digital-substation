# Цифровая подстанция IEC 61850

Учебный стенд для моделирования цифровой подстанции по стандарту IEC 61850.

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
├── src/
│   ├── mod_emulator.py
│   ├── rza_emulator.py
│   ├── goose_gen.py
│   ├── matrix_and_scenarios.py
│   ├── predict.py
│   └── ...
│
├── conf/
│   ├── conf_mod.yaml
│   ├── conf_rza1.yaml
│   ├── conf_rza2.yaml
│   └── ...
│
├── scripts/
│
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
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

---

## Авторы
Owliloop

...
