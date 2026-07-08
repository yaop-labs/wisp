# wisp — код-ревью перед первым пушем (2026-07-02)

Рабочий документ для прохода по находкам. Скоуп — вся кодовая база (~7600 строк Go).
Процесс: 8 независимых углов поиска → 44 кандидата → дедупликация → верификация каждого
кандидата по коду. Все находки ниже **подтверждены** с точными строками; ложных срабатываний
после верификации не осталось. `go build`, `go vet`, `gofmt -l`, `go test ./...` — чистые.

Формат: чекбокс + файл:строка + суть + сценарий отказа + подсказка к фиксу.
Номера строк соответствуют состоянию кода на 2026-07-02 (до любых правок).

---

## P0 — порча данных

- [ ] **1. relabel: `setLabel` мутирует общий backing array лейблов**
  `internal/processor/relabel/relabel.go:164`
  `setLabel` пишет `s.Attrs[i].Value = value` in place, а `Process` (relabel.go:78) копирует
  только структуру `Series` — слайс `Attrs` остаётся общим. `internal/source/host/host.go:239-244`
  строит один `attrs`-слайс (`device`) и передаёт его И в `node_network_receive_bytes_total`,
  И в `node_network_transmit_bytes_total`.
  **Отказ:** replace-правило, совпавшее только с receive-серией, переписывает лейбл transmit-серии →
  экспортируются неверные лейблы, ломаются ключи cardinality/reset ниже по пайплайну.
  **Фикс:** в `setLabel` при перезаписи существующего лейбла делать copy-on-write слайса Attrs
  (клонировать перед мутацией); дополнительно в host.go не шарить один attrs между сериями.

- [ ] **2. reset: гонка порядка батчей → вечный сдвиг счётчика**
  `internal/processor/reset/reset.go:66-68`
  Пайплайн раздаёт батчи `runtime.NumCPU()` воркерам из одного канала (pipeline.go:31, 79-82) без
  какого-либо порядка, а reset трактует `raw < st.lastRaw` как counter reset (`st.offset += st.lastRaw`).
  Мьютекс сериализует доступ к состоянию, но не порядок батчей.
  **Отказ:** при заторе очереди два скрейпа одного target'а обрабатываются в обратном порядке:
  воркер A записал lastRaw=1000 (новый батч), воркер B принёс 990 (старый) → offset += 1000 →
  все последующие значения счётчика завышены на 1000 до конца жизни агента; в amber — фантомный
  скачок rate(), который никогда не самокорректируется.
  **Фикс:** гарантировать per-source порядок (напр., шардировать батчи по источнику/target'у на
  воркеров по хэшу, или сравнивать timestamp батча и игнорировать более старые в reset-состоянии).

## P0 — shutdown-путь

- [ ] **3. pipeline: panic «send on closed channel» на graceful shutdown**
  `internal/pipeline/pipeline.go:124` (close), `:94` (send)
  `scrape.Stop` (scrape.go:177) и `host.Stop` (host.go:69) — no-op'ы: не джойнят ни Start-цикл, ни
  in-flight горутины `scrapeOne`/`collectAndEmit`. Pipeline запускает источники голым `go func()`
  (pipeline.go:104) без WaitGroup и после Stop'ов сразу делает `close(p.in)`.
  **Отказ:** SIGTERM во время скрейпа: горутина доходит до emit, в select готовы оба кейса
  (`p.in <- b` на закрытом канале и `ctx.Done()`), рантайм может выбрать send → panic, shutdown
  обрывается ДО flush spool. (Эталон: OTLP-receiver корректно ждёт in-flight через GracefulStop/Shutdown.)
  **Фикс:** WaitGroup на source-горутины (включая порождаемые scrapeOne) — Stop/Shutdown ждёт их
  завершения до `close(p.in)`; либо не закрывать канал, а сигналить воркерам отдельным done-каналом.

- [ ] **4. pipeline: дренаж очереди с уже отменённым контекстом**
  `internal/pipeline/pipeline.go:153` (drain), `:81` (воркеры на run-ctx)
  Воркеры стартуют с run-ctx (`go p.worker(ctx)`), который `signal.NotifyContext` отменяет по SIGTERM
  ДО вызова `a.Shutdown(stopCtx)` (main.go). Во время дренажа `process` передаёт мёртвый ctx в Export:
  otlp делает `context.WithTimeout(ctx, ...)` от отменённого (exporter.go:96) — мгновенный fail,
  retry тут же выходит по `ctx.Done()` (retry.go:47-48).
  **Отказ:** без spool (он опционален — app.go:179) до QueueSize=10000 батчей из очереди дропаются на
  КАЖДОМ graceful shutdown при здоровом downstream; со spool — бессмысленный круг через диск.
  **Фикс:** передавать в дренаж контекст Shutdown'а (stopCtx), а не run-ctx: например, хранить
  атомарно подменяемый ctx для process или явный drainCtx, устанавливаемый в Shutdown.

## P0 — spool (durability)

- [ ] **5. spool: poison-batch клинит drain навсегда + нет кодовых дефолтов лимитов**
  `internal/exporter/spool/spool.go:298-300`
  drain шлёт oldest-first и возвращается на первой же ошибке без классификации permanent/transient.
  При этом `config.go:203-207` и `app.go:180-183` не применяют НИКАКИХ дефолтов: MaxBytes=0
  (безлимит), MaxAge=0 (никогда не истекает) — значения 512MiB/6h существуют только в
  `configs/wisp.example.yaml:87-88`.
  **Отказ:** батч, который downstream отвергает перманентно (превышает gRPC max message size, 400),
  висит в голове → ни один более новый батч никогда не уйдёт, каталог растёт неограниченно.
  **Фикс:** (а) классифицировать перманентные ошибки (4xx/InvalidArgument/ResourceExhausted по размеру)
  и удалять/карантинить такой файл со счётчиком; (б) задать кодовые дефолты max_bytes/max_age в
  config-валидации/конструкторе, не полагаясь на example-YAML.

- [ ] **6. spool: нет fsync — «crash-safe» из doc-комментария не выполняется**
  `internal/exporter/spool/spool.go:195-199`
  Персистенция = `os.WriteFile(tmp)` + `os.Rename`, `Sync` в файле отсутствует вообще (ни данных,
  ни директории), при этом doc пакета (строка 5) обещает «crash-safe via temp-file + rename».
  drain молча удаляет некодируемые файлы (spool.go:287-296, только счётчик SpoolDropped).
  **Отказ:** Export вернул nil («принято = сохранено»), power loss до сброса page cache → нулевой/рваный
  .batch; после рестарта drain получает ошибку gob и молча удаляет файл → потеря принятых данных.
  **Фикс:** f.Sync() перед rename + fsync директории после rename (или честно ослабить обещание в doc);
  рваные файлы считать громче (warn-лог + отдельный счётчик).

## P1 — корректность данных и протокола

- [ ] **7. histogram: +Inf-наблюдения теряются при пустых конечных бакетах**
  `internal/source/scrape/histogram.go:82-84`
  Если все дельты конечных бакетов нулевые, `haveFinite=false` и дельта +Inf не добавляется никуда.
  **Отказ:** вход `x_bucket{le="0.1"} 0`, `x_bucket{le="+Inf"} 42`, `x_count 42` →
  ExpHistogram{Count:42, ZeroCount:0, бакетов нет} — Count > суммы бакетов, внутренне
  противоречивая точка для гистограммного движка amber.
  **Фикс:** при `!haveFinite` и ненулевой +Inf-дельте класть её в overflow-бакет (maxIdx) или в
  ZeroCount-эквивалент согласно семантике exp-histogram; добавить тест на этот вход.

- [ ] **8. model: инъекция разделителя в CanonicalKey (NUL + '=')**
  `internal/model/metric.go:118-124`
  Ключ = `name + "=" + value + "\x00"` без экранирования. OTLP-receiver пропускает значения
  атрибутов как есть (source/otlp/convert.go:98, anyValueString:105-106 — санитизации NUL нет).
  **Отказ:** `{a:"b"},{c:"d"}` и `{a:"b\x00c=d"}` дают одинаковый ключ → обход cardinality-бюджета
  (cardinality.go:63/98), слияние reset-состояний (reset.go:99) с порчей offset'ов, слияние разных
  ресурсов в один ResourceMetrics при экспорте (exporter convert.go:24). Вход контролируется
  внешним клиентом OTLP.
  **Фикс:** экранировать/длино-префиксовать пары в CanonicalKey (напр., писать len(name),name,len(value),value)
  или санитизировать NUL на входе receiver'а; тест на коллизию.

- [ ] **9. k8s discovery: opt-out вместо документированного opt-in**
  `internal/source/scrape/kubernetes.go:157`
  Исключаются только поды с `prometheus.io/scrape: "false"`, а doc пакета (kubernetes.go:22-23) и
  config.go:73-74 обещают opt-in («Pods opt in via the prometheus.io/scrape annotation»).
  **Отказ:** kubernetes_sd с `port: 8080` в namespace на 200 подов, из которых 3 с аннотацией:
  скрейпятся все 200 running-подов каждый интервал — лишние коннекты, флуд wisp_scrape_errors_total,
  мусор от случайно ответивших портов.
  **Фикс:** требовать `ann == "true"` (opt-in) как в доке; поведение opt-out — только явным флагом конфига.

- [ ] **10. otlp receiver: GracefulStop игнорирует shutdown-контекст**
  `internal/source/otlp/receiver.go:139-147`
  gRPC-ветка Stop зовёт `grpcSrv.GracefulStop()` без дедлайна и без fallback на `Stop()`
  (HTTP-ветка при этом корректно использует `httpSrv.Shutdown(ctx)`). pipeline.Shutdown зовёт
  Stop синхронно (pipeline.go:119).
  **Отказ:** клиент со stalled in-flight RPC (медленно льёт 16MB) держит GracefulStop бесконечно;
  15s-бюджет main.go не действует → оркестратор шлёт SIGKILL, flush spool не выполняется.
  **Фикс:** `GracefulStop()` в горутине + select на ctx.Done() с принудительным `grpcSrv.Stop()`.

- [ ] **11. app/config: TLS-поля молча игнорируются при `enabled: false`**
  `internal/app/app.go:83-92`, `internal/config/config.go:237-253`
  `clientTLS`/`serverTLS` возвращают nil при `c == nil || !c.Enabled`, отбрасывая
  ca_file/cert_file/client_ca_file; nil TLS = insecure dial у экспортера (exporter.go:117) и
  plaintext у приёмника (receiver.go:92). Validate вообще не проверяет TLS-блок.
  **Отказ:** оператор заполнил tls.ca_file/cert_file, забыл `enabled: true` → метрики и токены
  ходят открытым текстом без единого предупреждения.
  **Фикс:** в Validate — ошибка (или warn) «TLS fields set but enabled=false».

- [ ] **12. config: `sources: {otlp: {}}` проходит валидацию, агент работает вхолостую**
  `internal/config/config.go:257`, `internal/source/otlp/receiver.go:94,111,134`
  AnyEnabled проверяет только `s.OTLP != nil`; с пустыми grpc/http адресами Start пропускает оба
  listen-блока и блокируется на ctx.Done().
  **Отказ:** опечатка в ключах адресов → валидация проходит, /healthz 200, данных ноль.
  **Фикс:** в Validate требовать хотя бы один адрес (grpc или http) при включённом otlp-источнике.

- [ ] **13. parser: таб-разделитель не парсится (валиден по формату Prometheus)**
  `internal/source/scrape/parser.go:70`
  Строки без лейблов режутся `strings.Cut(line, " ")`; `name\t42` не содержит пробела → строка
  молча отбрасывается (parse() line 38-39), без ошибки скрейпа. Строки С лейблами идут через
  tab-толерантный `strings.Fields` — потеря избирательная и незаметная.
  **Фикс:** резать по `strings.IndexAny(line, " \t")` (или Fields) и для label-less строк.

- [ ] **14. selfobs: SamplesEmitted инкрементится ДО emit — двойной счёт при backpressure**
  `internal/source/scrape/scrape.go:282-283`, `internal/source/host/host.go:91-92`,
  `internal/source/otlp/receiver.go:178-179`
  Все три источника инкрементят счётчик до вызова emit, который может вернуть ErrBackpressure
  (уже посчитан в BackpressureShed, pipeline.go:89) или ctx.Err().
  **Отказ:** во время инцидента (spool выше high-water mark) emitted растёт с полной скоростью
  скрейпа при нулевом реальном входе → дашборды «loss = emitted - exported - shed» покажут ноль/минус.
  **Фикс:** перенести учёт в pipeline.emit после успешной постановки в очередь (см. также №32 —
  это заодно убирает дублирование учёта по источникам).

## P1 — инструментарий

- [ ] **15. `make lint` — молчаливый no-op (v1 бинарь vs v2 конфиг)**
  `Makefile:20`, `.golangci.yaml:1`
  Установлен golangci-lint v1.64.8, конфиг объявляет `version: "2"`; запуск падает с ошибкой версии,
  но `|| echo "golangci-lint not installed, skipping"` её глотает. Lefthook-хук, соответственно,
  тоже ничего не ловит. Именно поэтому пункты 16-19 дожили до ревью.
  **Фикс:** поставить golangci-lint v2; убрать `|| echo` (пусть make падает); в hook — то же.

- [ ] **16. gosec G112 (Slowloris): два http.Server без ReadHeaderTimeout**
  `internal/app/app.go:262` (selfobs-сервер), `internal/source/otlp/receiver.go:123` (OTLP HTTP)
  **Фикс:** задать ReadHeaderTimeout (и разумные Read/WriteTimeout) обоим серверам.

- [ ] **17. gosec G306/G301: права файлов/директории spool**
  `internal/exporter/spool/spool.go:195` (0o644 → 0o600), `spool.go:74` (0o755 → 0o750)
  Спул содержит полезную нагрузку метрик — мировая читаемость ни к чему.

- [ ] **18. errcheck: 6× непроверенный fmt.Fprintf в экспозиции метрик**
  `internal/selfobs/metrics.go:97-99,107-109`
  **Фикс:** либо проверять/игнорировать явно (`_, _ =`), либо добавить fmt.Fprintf для
  ResponseWriter в errcheck exclude.

- [ ] **19. Мелкие: unparam/copyloopvar/prealloc**
  `internal/exporter/otlp/exporter.go:159` — error-результат newHTTPTransport всегда nil;
  `internal/pipeline/pipeline.go:103` — копия loop-переменной не нужна (Go 1.22+);
  prealloc: `internal/exporter/spool/spool.go:337`, `internal/source/scrape/parser.go:22`.

---

## P2 — эффективность (агент долгоживущий, hot path важен)

- [ ] **20. CanonicalKey зовётся ~5× на серию за проход пайплайна**
  `internal/model/metric.go:110-125`; вызовы: cardinality.go:63,98; reset.go:99; exporter convert.go:24
  Каждый вызов — copy + sort.Slice + serialize, без кэша и без fast-path для уже отсортированных.
  При 100k серий/30s это сотни тысяч лишних сортировок/аллокаций за цикл.
  **Фикс:** fingerprint per series per batch (ленивое поле или пасс перед цепочкой процессоров);
  в CanonicalKey — проверка отсортированности одним проходом, скип copy+sort.

- [ ] **21. scrape: `string(body)` — вторая полная копия тела ответа (до 64MB)**
  `internal/source/scrape/scrape.go:301-305`
  **Фикс:** перевести parse на []byte. Нюанс: parseLabels (parser.go:227) отдаёт подстроки входа
  наружу — понадобятся точечные string-копии значений лейблов.

- [ ] **22. spool: ensureRoom делает полный ReadDir+stat+sort на КАЖДЫЙ enqueue**
  `internal/exporter/spool/spool.go:210-213` (единственный ранний выход — maxBytes<=0)
  Срабатывает под mutex именно во время аварии downstream.
  **Фикс:** ранний return когда `curBytes.Load()+need <= maxBytes` (счётчик уже поддерживается);
  листинг — только когда реально нужна эвикция.

- [ ] **23. relabel: ExpandString ×2 на правило на серию даже для литералов**
  `internal/processor/relabel/relabel.go:102-110`
  **Фикс:** в New() детектить отсутствие `$` в TargetLabel/Replacement и хранить как литералы;
  тогда apply — только MatchString.

- [ ] **24. parser: accumulateHist пересобирает ключ на каждую _bucket/_count/_sum строку**
  `internal/source/scrape/parser.go:165-166` (labelsWithoutLe + CanonicalKey на каждой строке; B+2 раза вместо 1)
  **Фикс:** кэш последнего (имя семейства, сырой label-текст без le) → *histAccum — бакеты семейства
  идут в экспозиции подряд.

- [ ] **25. cardinality: resource-ключ пересчитывается на каждую серию батча**
  `internal/processor/cardinality/cardinality.go:63` (+ то же в exporter convert.go:24)
  Все серии одного target'а шарят ОДИН resource-слайс (scrape.go:273-280, otlp convert.go:21).
  **Фикс:** мемоизация по идентичности слайса (сравнить с предыдущей серией) — один расчёт на ресурс.

## P2 — архитектура (altitude)

- [ ] **26. Reload жёстко завязан на конкретный scrape-source**
  `internal/app/app.go:40,218-227`
  **Фикс:** опциональная капабилити `Reloadable interface { Reload(cfg) error }` по образцу
  существующего Flusher (pipeline/interfaces.go:35-38) — источники сами владеют своей reload-семантикой.

- [ ] **27. stripMetaLabels вшит в ядро пайплайна**
  `internal/pipeline/pipeline.go:173`
  Ядро сканирует батчи ВСЕХ источников (host/otlp никогда не несут `__meta_`) ради convention
  одного source-типа, минуя абстракцию Processor.
  **Фикс:** оформить Processor'ом, автоматически добавляемым последней стадией цепочки.

- [ ] **28. Набор источников перечислен в трёх местах**
  `cmd/wisp/main.go:96-111`, `internal/config/config.go:256-258`, `internal/app/app.go:108-142`
  Новый источник = правки в трёх файлах; пропуск одного — тихая деградация.
  **Фикс:** одна таблица регистрации (имя → present-check + build func), которую итерируют все трое.

- [ ] **29. int/float-дуализм Point переизобретён в 5 местах**
  `internal/processor/reset/reset.go:79-96`, `internal/exporter/otlp/convert.go:74-78`,
  `internal/source/otlp/convert.go:47-52`, `internal/source/host/host.go:97-109`,
  `internal/source/scrape/parser.go:123-128`
  Контракт «оставаться на int64-пути пока значение целое» (модель значений amber) нигде не централизован.
  **Фикс:** model.Point.Value()/SetValue() с владением int-when-integral логикой; все 5 мест — на них.

- [ ] **30. /healthz знает единственный конкретный отказ — spool**
  `internal/app/app.go:250-256` (хардкод «spool unhealthy: durability layer failing», app.go:192)
  **Фикс:** мини-реестр именованных `func() error`-чеков; spool регистрируется сам, handler generic.

- [ ] **31. Учёт emit и политика логов продублированы в каждом источнике**
  `internal/source/host/host.go:91-92`, `scrape.go:282-283`, `receiver.go:178-179`
  Классификация `err != nil && ctx.Err() == nil && !errors.Is(err, ErrBackpressure)` повторяется
  по источникам; новый источник, забывший её, флудит логами при каждом backpressure.
  **Фикс:** перенести SamplesEmitted и политику логирования в pipeline.emit (там уже считается
  BackpressureShed) — источники просто вызывают emit. Заодно закрывает №14.

## P2 — переиспользование

- [ ] **32. k8s inClusterClient дублирует tlsconfig**
  `internal/source/scrape/kubernetes.go:64-73` = `tlsconfig.Client(Settings{CAFile: saCAFile})`
  (tlsconfig.go:35-47, import-цикла нет). Хардениг tlsconfig иначе не дойдёт до k8s-клиента.

- [ ] **33. Пять копий label-хелперов по трём пакетам**
  Линейный lookup: relabel.go:140-155, parser.go:278-285. Filter-копирование: relabel.go:178-186,
  parser.go:268-276, pipeline.go:199-216.
  **Фикс:** model.Labels.Get(name) и model.Labels.Filter(keep func(string) bool).

- [ ] **34. Три реализации «sorted keys of map[string]string»**
  `internal/exporter/otlp/exporter.go:202-212` (= байт-в-байт `redact.Keys`, redact.go:18-28) +
  `internal/app/app.go:327-331` (ручной collect+sort).
  **Фикс:** всё это `slices.Sorted(maps.Keys(m))` — go.mod уже 1.26.

- [ ] **35. Сниппет тела HTTP-ошибки: 2 копии + 1 потерянная**
  `internal/exporter/otlp/exporter.go:192` и `kubernetes.go:117` — одинаковый
  `io.ReadAll(io.LimitReader(body, 256))`; `scrape.go:299` — только `"status %d"` без сниппета.
  **Фикс:** общий хелпер (напр. internal/httpx.ErrorFromResponse), использовать во всех трёх.

- [ ] **36. Два генератора тестовых сертификатов**
  `internal/source/otlp/tls_test.go:29` (genCerts) vs `internal/tlsconfig/tlsconfig_test.go:20`
  (writeCertAndCA) — одинаковый ECDSA P-256 CA + PEM-запись в TempDir.
  **Фикс:** общий test-хелпер (internal/testutil или tlsconfig/tlstest), оставить более богатый genCerts.

## P2 — упрощение

- [ ] **37. spool: блок «Remove + учёт» скопипащен в 4 местах**
  `internal/exporter/spool/spool.go:218-222` (ensureRoom), `:259-263` (expireOld), `:291-295` и
  `:302-306` (drain); плюс теневой `total` в ensureRoom (строки 214, 219) дублирует curBytes.
  **Фикс:** хелпер `removeFile(f, counter)`; ensureRoom крутится по curBytes.Load().

- [ ] **38. pipeline.Stats() и три атомика никем не читаются в проде**
  `internal/pipeline/pipeline.go:55,92,97,179,184` — единственный читатель pipeline_flow_test.go:83;
  дублируют selfobs.
  **Фикс:** удалить поля и Stats(); тест перевести на selfobs-счётчики или fake-экспортер.

- [ ] **39. selfobs: каждая метрика объявлена дважды (var + registry)**
  `internal/selfobs/metrics.go:21-39` и `:46-64` — 17 счётчиков, ничто не проверяет соответствие;
  забытая регистрация молча не попадает на /metrics (gauges при этом самрегистрирующиеся, :80).
  **Фикс:** самрегистрирующийся конструктор `newCounter(name, help)`.

- [ ] **40. scrape Config.Timeout — мёртвый конфиг**
  `internal/source/scrape/scrape.go:57,86-89` — в YAML ключа нет (config.go:65-71),
  scrapeConfigFrom (app.go:65) не заполняет → в проде всегда timeout=interval.
  **Фикс:** либо провести ключ `timeout` через config.ScrapeSource, либо удалить поле.

- [ ] **41. host: 4 одинаковых блока `if s.enabled(X) { append(... s.X(now)...) }`**
  `internal/source/host/host.go:74-85` (load/memory/cpu/network).
  **Фикс:** таблица name→collector; заодно единый список для валидации имён коллекторов.

- [ ] **42. histogram: lastFinite — избыточное состояние**
  `internal/source/scrape/histogram.go:68`
  le отсортированы по возрастанию (histogram.go:58), expIndex монотонен → lastFinite всегда == maxIdx
  при haveFinite.
  **Фикс:** убрать lastFinite, использовать maxIdx под haveFinite. (Делать вместе с №7 — та же функция.)

---

## Что уже хорошо (не трогать)

- Композиция экспортеров: otlp → retry → spool как декораторы, Flusher как опциональная
  капабилити — правильная архитектура, менять не нужно.
- Regex'ы relabel компилируются один раз при построении конфига.
- OTLP-receiver корректно ждёт in-flight запросы (HTTP-ветка Shutdown(ctx)) — образец для №3/№10.
- Тесты: 17 пакетов, race-clean; build/vet/fmt чистые.

## Рекомендованный порядок фиксов

1. §P0 (1-6) — порча данных, shutdown, durability. После каждого фикса: `go test ./... -race`.
2. №15 (lint-гейт) — поставить golangci-lint v2, затем №16-19 закрыть по выводу линтера.
3. §P1 (7-14) — корректность протокола/конфига.
4. §P2 — cleanup; №31 закрывает №14, №42 делать вместе с №7, №34/№33 — механические.
