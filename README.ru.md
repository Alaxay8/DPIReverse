# DPIReverse

[English](README.md) | [Русский](README.ru.md)

---

## Для кого это?

1. **Сетевые инженеры и исследователи:** Для анализа и понимания механизмов цензуры и поведения систем DPI.
2. **Правозащитники и цифровые активисты:** Для сбора технических доказательств интернет-цензуры и сетевого вмешательства.
3. **Разработчики инструментов обхода блокировок:** Для сбора данных о том, как блокируется сетевой трафик, что помогает создавать более эффективные стратегии обхода.

## Обзор

DPIReverse — инструмент black-box анализа сети для определения поведения Deep Packet Inspection по внешне наблюдаемым сетевым эффектам.

Сканер генерирует контролируемые вариации транспорта и TLS, измеряет реакцию сетевого пути и применяет дифференциальный анализ на основе правил для оценки вероятного поведения фильтрации.

Используйте DPIReverse только для сетей и сервисов, на тестирование которых у вас есть разрешение.

## Возможности

- Модульная чистая архитектура со слоями generator, transport, measurement, analyzer, orchestrator и report.
- MVP с фокусом на TLS: профили ClientHello в стиле Chrome и случайные, поддержка TLS 1.2 и 1.3, вариации SNI и фрагментированные рукопожатия.
- Структурированный вывод измерений с задержкой, статусом успешности и классификацией ошибок.
- Подключаемый rule engine для вывода гипотез о поведении DPI.
- Интеллектуальная итоговая таблица с анализом по уровням OSI (L3/L4/L7).
- Поддержка SOCKS5-прокси для анонимных исследований.
- Рандомизация задержек (Jitter) для защиты от обнаружения и rate-limiting.
- Человекочитаемые CLI-отчеты и машиночитаемый JSON-вывод.
- Параллельное выполнение экспериментов с настраиваемым числом повторов.

## Быстрый старт

```bash
go mod tidy
go run . scan youtube.com
```

### Быстрая установка (одной командой)

```bash
wget -qO- https://raw.githubusercontent.com/Alaxay8/DPIReverse/v1.0.0/scripts/install.sh | bash
```

### Удаление

```bash
wget -qO- https://raw.githubusercontent.com/Alaxay8/DPIReverse/v1.0.0/scripts/uninstall.sh | bash
```

### Ручная установка

```bash
git clone https://github.com/Alaxay8/DPIReverse.git
cd DPIReverse
go mod tidy
go build -o dpi .
```

## Использование

Запуск быстрого текстового отчета:

```bash
dpi scan youtube.com --profile quick --format text
```

Запуск полного профиля через прокси с выводом JSON:

```bash
dpi scan youtube.com --profile full --proxy socks5://127.0.0.1:9050 --format json --repeats 3
```

Основные флаги:

- `--target`: имя хоста для сканирования.
- `--port`: порт назначения. По умолчанию `443`.
- `--profile`: `quick` или `full`.
- `--proxy`: URL SOCKS5 прокси (например, `socks5://127.0.0.1:9050`).
- `--format`: `text` или `json`.
- `--repeats`: число попыток на тест-кейс.
- `--timeout`: таймаут одной попытки, например `5s`.
- `--concurrency`: число worker goroutine.
- `--log-level`: `debug`, `info` или `warn`.

## Примеры

Пример текстового вывода:

```text
DPI Analysis Report
Target: example.com:443
Profile: quick
Window: 2026-04-12T10:00:00Z -> 2026-04-12T10:00:06Z
Overall confidence: 0.72

Findings:
- Baseline SNI failed while alternate SNI variants succeeded on the same endpoint. (Yes, confidence 0.84)
- Fragmented TLS handshakes succeeded where the baseline handshake failed. (Yes, confidence 0.76)
- No JA3-based blocking evidence observed. (No, confidence 0.28)
```

Пример фрагмента JSON:

```json
{
  "analysis": {
    "dpi_profile": {
      "sni_filtering": true,
      "ja3_blocking": false,
      "fragmentation_bypass": true
    },
    "confidence": 0.72
  }
}
```

## Конфигурация

Текущее MVP поставляется со встроенными TLS-профилями экспериментов `quick` и `full`.

Каждый сгенерированный тест-кейс содержит структурированные теги, например `client_hello`, `tls_version`, `sni_mode` и `fragmented`. Эти теги являются контрактом для analyzer, что упрощает добавление новых транспортных экспериментов и правил.

## Разработка

Запуск форматирования и тестов:

```bash
gofmt -w $(find . -name '*.go' -print)
go test ./...
```

Структура проекта:

```text
DPIReverse/
├── cmd/
├── configs/
├── internal/
│   ├── analyzer/
│   ├── generator/
│   ├── measurement/
│   ├── orchestrator/
│   ├── report/
│   └── transport/
├── pkg/
└── main.go
```

## Лицензия

MIT
