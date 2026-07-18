# Journald collection

Wisp reads the systemd journal through `journalctl -o export` and emits OTLP
Logs. The source does not link against `libsystemd` and does not require cgo.
`journalctl` must be present in `PATH` when Wisp starts.

The wire parser follows systemd's
[Journal Export Format](https://systemd.io/JOURNAL_EXPORT_FORMATS/); command
selection and cursor behavior follow the
[`journalctl` manual](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html).

## Configuration

```yaml
sources:
  journald:
    checkpoint_file: /var/lib/wisp/journald-checkpoint.json
    poll_interval: 1s
    timeout: 10s
    start_at: end
    max_entries_per_poll: 512
    max_field_bytes: 262144
    max_batch_bytes: 524288
    units:
      - checkout.service
    identifiers:
      - checkout-worker
    redaction:
      patterns:
        - '(?i)authorization:\s*bearer\s+\S+'
        - 'token=[^&\s]+'
      replacement: '[REDACTED]'
```

All fields except `checkpoint_file` are optional:

- `poll_interval` defaults to `1s` and must be at least `100ms`;
- `timeout` bounds one `journalctl` invocation, including parsing and durable
  admission. It defaults to `10s` and must be between `1s` and `1m`;
- `start_at` is `end` by default. `beginning` reads the oldest retained
  matching entry when no checkpoint exists;
- `max_entries_per_poll` defaults to `512` and is bounded to `1..10000`;
- `max_field_bytes` defaults to 256 KiB and bounds `MESSAGE` allocation;
- `max_batch_bytes` defaults to 512 KiB, has an 8 KiB minimum, and bounds the
  encoded log-record content assembled into one OTLP batch. Wisp may lower both
  limits to fit the configured OTLP Logs and spool limits;
- `units` maps to repeated `journalctl --unit` filters;
- `identifiers` maps to repeated `journalctl --identifier` filters.

`directory` may point at an absolute, non-root directory containing journal
files, for example `/host/var/log/journal` in a container:

```yaml
sources:
  journald:
    checkpoint_file: /var/lib/wisp/journald-checkpoint.json
    directory: /host/var/log/journal
```

Wisp requires a `journalctl` version with Journal Export Format and
`--output-fields` support (systemd 236 or newer). An explicitly configured
journald source fails startup if `journalctl` cannot be resolved.

## Delivery and checkpoints

The checkpoint is a versioned JSON document written through temp-file write,
file fsync, atomic rename, and parent-directory fsync. It contains the last
durably admitted journal cursor.

For a new `start_at: end` source, Wisp first persists the current realtime
boundary and queries from that boundary. This avoids replaying old retained
entries while also avoiding the gap that would occur if Wisp queried the last
entry and saved its cursor later. `start_at: beginning` starts at the oldest
retained matching entry.

For each batch:

1. Wisp parses and bounds journal entries;
2. configured redaction is applied to `MESSAGE`;
3. the OTLP Logs envelope is delivered or fsynced into the shared spool;
4. only then is the final cursor atomically checkpointed.

This gives at-least-once delivery. A crash after durable admission but before
the cursor rename can repeat the last batch; it cannot silently skip it.
Admission failure or spool pressure leaves the cursor unchanged and retries
the entry. A checkpoint write failure pauses collection and makes readiness
fail until the same in-memory cursor is persisted.

The checkpoint belongs to the exact filter set. Changing `units`,
`identifiers`, `directory`, or `start_at` requires a restart. If an operator
deliberately changes the journal stream, they should use a new checkpoint path
or remove the old checkpoint while Wisp is stopped.

An invalid or inaccessible cursor is fail-safe: `journalctl` failure makes Wisp
unready and collection retries without advancing state. To accept a deliberate
gap after journal vacuum or replacement, stop Wisp, remove the checkpoint, and
restart with the desired `start_at` policy.

## Bounded parsing and loss policy

Journal Export Format supports both newline-delimited UTF-8 fields and
length-framed binary fields. Wisp parses both. Field order is not assumed.
Unwanted fields and oversized binary values are streamed to a discard sink
instead of being allocated.

If `MESSAGE` exceeds `max_field_bytes`, Wisp admits the record with an empty
body and `wisp.journald.message_oversized=true`, then advances the cursor only
after that marker is durable. A missing `MESSAGE` is similarly marked with
`wisp.journald.message_missing=true`. This avoids an oversized record wedging
the stream while making content loss explicit.

If the encoded record still exceeds `max_batch_bytes` because of combined
metadata, Wisp replaces it with a minimal durable marker carrying the cursor,
timestamp, severity, and `wisp.journald.record_oversized=true`.

Redaction uses Go RE2 regular expressions, so evaluation has no catastrophic
backtracking. Rules run in order and replacement text is literal. If
replacement expansion would exceed `max_field_bytes`, the record is
intentionally dropped; queued earlier records are admitted and checkpointed
first, then the dropped record cursor is persisted. Secret-bearing original
content is never used as a fallback.

## OTLP mapping

- `__REALTIME_TIMESTAMP` becomes `time_unix_nano`;
- Wisp collection time becomes `observed_time_unix_nano`;
- syslog priority `0..7` maps to OTLP fatal, error, warning, notice, info, and
  debug severity levels;
- selected systemd, syslog, process, user, host, transport, and boot fields
  become bounded log attributes;
- `wisp.journald.cursor` records the source cursor for duplicate diagnosis;
- configured Wisp resource attributes remain OTLP Resource attributes;
- instrumentation scope is `github.com/yaop-labs/wisp/journald`.

Wisp does not forward `_CMDLINE`, environment variables, or arbitrary journal
fields by default because those surfaces commonly contain credentials or
unbounded application-specific data.

## Permissions and self-observability

The Wisp process must be able to read the selected journals. On common Linux
distributions this means root or membership in an appropriate group such as
`systemd-journal`; exact policy is distribution-specific. In a container, mount
the journal directory read-only and make the relevant group IDs available.

The source exports:

- `wisp_journald_records_total`;
- `wisp_journald_batches_total`;
- `wisp_journald_read_errors_total`;
- `wisp_journald_checkpoint_errors_total`;
- `wisp_journald_admission_errors_total`;
- `wisp_journald_backpressure_total`;
- `wisp_journald_oversized_messages_total`;
- `wisp_journald_oversized_records_total`;
- `wisp_journald_redaction_matches_total`;
- `wisp_journald_redaction_dropped_records_total`.

Subprocess, permission, parser, and checkpoint failures affect `/readyz`.
Liveness remains process-local.
