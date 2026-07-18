# File log collection

Status: first bounded file-tailing increment implemented in the `v0.9.x`
development line.

Wisp tails newline-delimited regular files on Linux and emits native OTLP Logs
requests into the same retry and signal-neutral spool path used by the OTLP
receiver. File records bypass metric-only processors.

```yaml
sources:
  filelog:
    include: ["/var/log/my-app/*.log"]
    exclude: ["/var/log/my-app/*.gz"]
    checkpoint_file: "/var/lib/wisp/filelog-checkpoints.json"
    poll_interval: 1s
    start_at: end
    max_line_bytes: 262144
    max_batch_bytes: 524288
    max_read_bytes_per_poll: 4194304
```

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

Timestamp parsing, multiline framing, CRI metadata, and content redaction are
separate later increments. The current record observed time is the collection
time.

## Durability and duplicate boundary

The checkpoint is a bounded, versioned JSON document. Wisp writes a temporary
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

If a rotated inode is deleted before Wisp can find it, its unread suffix is no
longer recoverable; `wisp_filelog_rotation_misses_total` records this. A
copy-truncate followed by regrowth beyond the previous offset entirely between
polls cannot be distinguished from a normal append in this first increment.
Use rename-based rotation where lossless collection matters.

## Bounds and self-observability

`max_line_bytes`, `max_batch_bytes`, and `max_read_bytes_per_poll` bound memory
and per-file work. Include/exclude discovery is deterministic, and the
checkpoint file itself is always excluded from collection.
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
- `wisp_filelog_backpressure_total`.
