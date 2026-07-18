# File log collection

Status: bounded text and Kubernetes CRI file tailing implemented in the
`v0.9.x` development line.

Wisp tails newline-delimited regular files on Linux in either `text` or `cri`
mode and emits native OTLP Logs requests into the same retry and signal-neutral
spool path used by the OTLP receiver. File records bypass metric-only
processors.

```yaml
sources:
  filelog:
    include: ["/var/log/my-app/*.log"]
    exclude: ["/var/log/my-app/*.gz"]
    checkpoint_file: "/var/lib/wisp/filelog-checkpoints.json"
    poll_interval: 1s
    start_at: end
    format: text
    max_line_bytes: 262144
    max_batch_bytes: 524288
    max_read_bytes_per_poll: 4194304
```

`format` is `text` by default. It is one setting for the whole filelog source;
use a separate Wisp process if unrelated include patterns require different
framing.

`start_at` applies only when an identity is first discovered. `end` avoids
unexpectedly replaying a historical file on first installation; `beginning`
imports it. A new identity that replaces a known path is a rotation and is
always read from the beginning.

Each record contains:

- its UTF-8 body (invalid input bytes are replaced, never passed as an invalid
  protobuf string);
- `log.file.path`;
- `wisp.file.offset`, the byte position at which the record began;
- configured Wisp resource attributes;
- instrumentation scope `github.com/yaop-labs/wisp/filelog`.

In `text` mode the record observed time is the collection time and no event
timestamp is inferred.

## Bounded multiline framing

Text mode can join physical lines into one logical record using a start
pattern:

```yaml
sources:
  filelog:
    format: text
    multiline:
      start_pattern: '^\d{4}-\d{2}-\d{2}T'
      max_lines: 256
      flush_after: 5s
```

A matching line starts a record. Following non-matching lines are appended
with one `\n`; the next matching line completes the previous record. A
non-matching line encountered without a pending record starts an orphan record
instead of being discarded. Multiline cannot be combined with CRI framing,
which already has its own `P…F` record boundaries.

An active file's final record remains uncheckpointed until one of these
boundaries:

- the next start-pattern match;
- the file has not been modified for `flush_after`;
- its inode is drained during rotation.

The default `flush_after` is 5 seconds. Timeout and rotation completions carry
`wisp.multiline.flush_reason` so downstream can distinguish inferred
boundaries. Before a boundary, restart rereads from the pending record's first
physical line; no unbounded body is serialized into the checkpoint.

`max_line_bytes` bounds the assembled body, `max_lines` defaults to 256 and is
limited to 4096, and the physical span must fit one
`max_read_bytes_per_poll` window once reading begins at the record. When any
bound is exceeded, Wisp drops the whole logical record and persists a bounded
drop state while skipping continuations. Collection resumes automatically at
the next line matching `start_pattern`. This prevents an unending stack trace
or stream of empty continuations from wedging the file.

Redaction runs after multiline assembly, so a rule may intentionally match
across joined lines with an RE2 `(?s)` expression.

## Text event timestamps

Text records can extract an explicit event timestamp:

```yaml
sources:
  filelog:
    format: text
    timestamp:
      pattern: '^(\S+)'
      format: rfc3339nano
```

The RE2 pattern must contain exactly one capture group. Wisp applies it to the
fully framed logical body before redaction and limits the captured value to
128 bytes. Supported formats are:

- `rfc3339` and `rfc3339nano`, including an explicit `Z` or numeric offset;
- `unix`, `unix_ms`, `unix_us`, and `unix_ns` as unsigned epoch values.

Wisp deliberately does not guess timezone, timestamp position, unit, or a
custom locale. CRI already supplies its own event time and cannot be combined
with this block.

When capture or parsing fails, the log is retained with OTLP
`time_unix_nano` unset and collection time in `observed_time_unix_nano`.
Successes and failures are counted, including work repeated after an admission
retry.

## Content redaction before durability

Redaction is opt-in and runs on the fully framed logical body before Wisp
creates an OTLP request, calls the exporter, or writes an envelope to the
spool:

```yaml
sources:
  filelog:
    # ...include, checkpoint, and bounds...
    redaction:
      patterns:
        - '(?i)authorization:\s*bearer\s+\S+'
        - 'token=[^&\s]+'
      replacement: '[REDACTED]'
```

Rules use Go's RE2-compatible regular expressions and execute in configured
order. The replacement is literal, not a `$1` expansion. An omitted or empty
replacement defaults to `[REDACTED]`. Redaction applies equally to text
records, assembled CRI `P…F` content, rotated CRI partials, and malformed CRI
lines retained as raw records.

The privacy boundary is deliberately bounded:

- 1–16 patterns;
- at most 1024 bytes per pattern;
- at most 256 printable UTF-8 bytes in the replacement;
- patterns matching empty input are rejected;
- every intermediate result must remain within `max_line_bytes`.

If replacement expansion would exceed `max_line_bytes`, Wisp never constructs
or persists the expanded record. It intentionally drops that record, advances
the checkpoint, and increments
`wisp_filelog_redaction_dropped_records_total`. This is an explicit
privacy-over-availability choice: the original secret-bearing content is not
used as a fallback.

`wisp_filelog_redaction_matches_total` counts replacements, including repeated
work after an admission retry. Pattern text and replacement content are not
written to normal Wisp logs.

## Kubernetes CRI framing

Use the actual pod files rather than the convenience symlinks under
`/var/log/containers`:

```yaml
sources:
  filelog:
    include: ["/var/log/pods/*/*/*.log"]
    exclude: ["/var/log/pods/*/*/*.gz"]
    checkpoint_file: "/var/lib/wisp/filelog-checkpoints.json"
    format: cri
    kubernetes:
      pod_logs_root: /var/log/pods
```

CRI mode accepts the runtime framing contract:

```text
<RFC3339Nano timestamp> <stdout|stderr> <P|F> <content>
```

- `F` produces a complete record. Its CRI timestamp becomes OTLP
  `time_unix_nano`; collection time remains `observed_time_unix_nano`.
- `log.iostream` is `stdout` or `stderr`.
- Consecutive `P` fragments followed by `F` are concatenated exactly, with no
  inserted delimiter. The timestamp, stream, and `wisp.file.offset` come from
  the first fragment.
- A stream change terminates the pending sequence as a
  `wisp.cri.partial=true`, `wisp.cri.sequence_error=true` record, then handles
  the new fragment independently.
- A malformed physical line is preserved as its raw body with
  `wisp.cri.parse_error=true`. It is not silently discarded.
- An unterminated sequence in an active file remains pending. When a rotated
  inode is drained, it is emitted with `wisp.cri.partial=true`.

Pending `P` fragments are intentionally not stored in the checkpoint. Until
their `F` is durably admitted, the checkpoint remains at the first fragment
and a restart rereads the sequence. This keeps the checkpoint bounded without
weakening the at-least-once contract.

Read `/var/log/pods/*/*/*.log` directly when lossless rotation recovery
matters. `/var/log/containers/*.log` entries are normally symlinks; Wisp can
tail their current targets, but cannot reliably find an old target inode by
scanning the symlink directory after replacement.

### Kubernetes resource enrichment

The optional `kubernetes` block enables bounded, API-free enrichment from the
kubelet pod log path. `pod_logs_root` defaults to `/var/log/pods` when the
block is present and can point at a custom kubelet `podLogsDir` or its mounted
location inside the Wisp container. It must be an absolute path other than
the filesystem root. Enrichment requires `format: cri`.

For a recognized path:

```text
<pod_logs_root>/<namespace>_<pod>_<pod UID>/<container>/<restart count>.log
```

Wisp adds these OTLP Resource attributes:

- `k8s.namespace.name`;
- `k8s.pod.name`;
- `k8s.pod.uid`;
- `k8s.container.name`;
- `k8s.container.restart_count` as an integer.

Path-derived values override conflicting global `resource.attributes` for
that file because they describe the more specific telemetry resource. They
also participate in the durable envelope's bounded string identity, except
for the integer restart count.

Wisp does not infer `service.name`, cluster, node, workload owner, labels,
annotations, image, or container runtime identity from a filename. An
unrecognized or unsafe path does not drop the log; Wisp retains the base
resource and increments the enrichment-miss counter.

The attribute names follow the
[OpenTelemetry Kubernetes resource semantic conventions](https://opentelemetry.io/docs/specs/semconv/resource/k8s/).
Kubernetes documents `/var/log/pods` as the default and permits a custom
`podLogsDir`; operators must set `pod_logs_root` to the path visible inside
Wisp.

#### Optional Kubernetes API enrichment

An `api` block adds metadata that cannot be derived safely from the log path:

```yaml
sources:
  filelog:
    format: cri
    kubernetes:
      pod_logs_root: /var/log/pods
      api:
        timeout: 2s
        cache_ttl: 5m
        stale_after: 1h
        failure_retry: 30s
        max_pods: 10000
        workers: 2
        labels:
          - app.kubernetes.io/name
          - app.kubernetes.io/version
```

Wisp uses the in-cluster API endpoint, projected service-account token, and
cluster CA. Token content is reread for every request so projected-token
rotation does not require an agent restart. Enabling the block is explicit:
missing in-cluster environment, token, or CA fails startup instead of silently
pretending enrichment is active.

Runtime enrichment is fail-open and asynchronous. A new pod log immediately
uses its path-derived identity and schedules a bounded metadata GET; no API
request runs in the file read/admission path. The first records from a newly
seen or very short-lived pod can therefore contain only path metadata.
Subsequent records use the cache. API outages never pause or drop logs.

The cache is keyed by path-derived Pod UID. A Pod response is accepted only
when its UID exactly matches the log path, preventing a reused namespace/name
from contaminating rotated logs. Fresh values are used for `cache_ttl`.
Refresh failures retain the last value only until `stale_after`; failed
lookups are retried after `failure_retry`. The cache, worker count, request
duration, response body, token file, label count, and refresh queue are all
bounded. `max_pods` uses least-recently-used-time eviction. Records using a
stale cache entry carry `wisp.kubernetes.api.stale=true`.

Successful lookups may add:

- `k8s.node.name`;
- direct workload identity: `k8s.replicaset.name`,
  `k8s.statefulset.name`, `k8s.daemonset.name`, or `k8s.job.name`;
- `k8s.deployment.name` after a ReplicaSet owner lookup;
- `k8s.cronjob.name` after a Job owner lookup;
- `container.id`, `container.image.name`, `container.image.id`, and
  `oci.manifest.digest` for regular, init, or ephemeral containers;
- only explicitly allowlisted labels as `k8s.pod.label.<original key>`.

Annotations and arbitrary labels are deliberately not copied: both are common
credential/privacy and cardinality surfaces. API metadata augments but never
overrides path-derived namespace, pod UID/name, container name, or restart
count; it does override less-specific conflicting global resource values.

Minimum namespace-wide RBAC for full workload resolution is:

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get"]
  - apiGroups: ["apps"]
    resources: ["replicasets"]
    verbs: ["get"]
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["get"]
```

The ReplicaSet and Job permissions are optional; without them Pod, node,
container, label, and direct owner metadata still works, while owner lookup
errors remain observable. Scope Role bindings to the namespaces whose pod log
directories Wisp reads.

## Durability and duplicate boundary

The checkpoint is a bounded, versioned JSON document. Version 2 added the
bounded CRI oversized-sequence continuation state; version 3 adds the
equivalent multiline continuation state. Wisp reads versions 1 and 2 and
upgrades them on the next write. Older binaries reject newer versions
explicitly instead of silently resetting offsets, so rolling back requires
retaining a compatible checkpoint or accepting an operator-selected
`start_at` boundary.

Wisp writes a temporary
file, fsyncs it, renames it atomically, and fsyncs the parent directory.
Unknown fields, unsupported versions, negative offsets, relative paths, and
oversized checkpoint documents fail startup instead of silently resetting
collection.

For every batch the order is:

1. create a lossless OTLP Logs envelope;
2. export it or fsync it into the shared spool;
3. advance and atomically persist the file checkpoint.

An admission failure therefore leaves the checkpoint unchanged and retries the
same batch. A crash after step 2 but before step 3 can replay that batch. This
is the intentional at-least-once duplicate boundary; `wisp.file.offset`,
resource identity, and Wisp's delivery envelope ID make the boundary
observable.

Checkpoint persistence failure makes Wisp unready and pauses further reads
until the in-memory checkpoint can be persisted. It does not repeatedly emit
the already accepted batch.

## Rotation, truncation, and partial records

Identity is Linux device plus inode, not pathname.

- When a configured path gets a new identity, Wisp scans its parent directory
  (bounded to 4096 entries) for the checkpointed inode, drains it, then starts
  the replacement at offset zero. This works after process restart.
- A rotated file's final non-newline-terminated record is flushed before Wisp
  moves to the replacement. Rotation schemes should rename after writers have
  stopped using the old file.
- Same-inode size regression is treated as truncation and restarts at offset
  zero.
- A partial record in an active file is not emitted or checkpointed until its
  newline arrives.
- Lines over `max_line_bytes` are discarded through a bounded continuation
  state, so a single arbitrarily large line cannot wedge collection.
- In CRI mode the same bound applies to the assembled logical content.
  Oversized `P…F` sequences are skipped with a persisted continuation bit, so
  restart does not replay an unbounded prefix.

If a rotated inode is deleted before Wisp can find it, its unread suffix is no
longer recoverable; `wisp_filelog_rotation_misses_total` records this. A
copy-truncate followed by regrowth beyond the previous offset entirely between
polls cannot be distinguished from a normal append in this first increment.
Use rename-based rotation where lossless collection matters.

## Bounds and self-observability

`max_line_bytes`, `max_batch_bytes`, and `max_read_bytes_per_poll` bound memory
and per-file work. A CRI physical line gets only a small fixed header allowance
above `max_line_bytes`. A fragmented logical record must also reach `F` within
one `max_read_bytes_per_poll` span once reading starts at its first fragment;
otherwise Wisp enters the same persisted oversized-sequence drop state. This
prevents a stream of empty `P` fragments from defeating the content bound.

Include/exclude discovery is deterministic, and the checkpoint file itself is
always excluded from collection.
Wisp lowers the effective line/batch bounds when necessary to fit the
configured Logs request and spool budgets, reserving protobuf/envelope
metadata space.

Self-observability includes:

- `wisp_filelog_active_files`;
- `wisp_filelog_records_total` and `wisp_filelog_batches_total`;
- `wisp_filelog_bytes_read_total`;
- `wisp_filelog_oversized_records_total`;
- `wisp_filelog_rotations_total` and
  `wisp_filelog_rotation_misses_total`;
- `wisp_filelog_truncations_total`;
- `wisp_filelog_checkpoint_errors_total`;
- `wisp_filelog_read_errors_total`;
- `wisp_filelog_admission_errors_total`;
- `wisp_filelog_backpressure_total`;
- `wisp_filelog_cri_fragments_total`;
- `wisp_filelog_cri_parse_errors_total`;
- `wisp_filelog_cri_sequence_errors_total`;
- `wisp_filelog_cri_partial_records_total`;
- `wisp_filelog_kubernetes_enriched_records_total`;
- `wisp_filelog_kubernetes_enrichment_misses_total`;
- `wisp_filelog_kubernetes_api_cache_entries`;
- `wisp_filelog_kubernetes_api_cache_hits_total`,
  `wisp_filelog_kubernetes_api_cache_misses_total`, and
  `wisp_filelog_kubernetes_api_stale_hits_total`;
- `wisp_filelog_kubernetes_api_refreshes_total`,
  `wisp_filelog_kubernetes_api_errors_total`, and
  `wisp_filelog_kubernetes_api_owner_errors_total`;
- `wisp_filelog_kubernetes_api_enriched_records_total`;
- `wisp_filelog_kubernetes_api_uid_mismatches_total`;
- `wisp_filelog_kubernetes_api_queue_drops_total` and
  `wisp_filelog_kubernetes_api_evictions_total`;
- `wisp_filelog_redaction_matches_total`;
- `wisp_filelog_redaction_dropped_records_total`;
- `wisp_filelog_multiline_forced_flushes_total`;
- `wisp_filelog_multiline_oversized_records_total`;
- `wisp_filelog_timestamp_parsed_total`;
- `wisp_filelog_timestamp_errors_total`.

All filelog collection features are opt-in where they expand privileges,
content inspection, or metadata cardinality.
