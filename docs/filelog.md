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

## Durability and duplicate boundary

The checkpoint is a bounded, versioned JSON document. Version 2 adds the
bounded CRI oversized-sequence continuation state. Wisp reads version 1 and
upgrades it on the next write. A pre-CRI binary rejects version 2 explicitly
instead of silently resetting offsets, so rolling back requires retaining a
compatible checkpoint or accepting an operator-selected `start_at` boundary.

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
- `wisp_filelog_cri_partial_records_total`.

Multiline application parsing beyond CRI runtime fragments, content
redaction, Kubernetes metadata enrichment, and journald collection remain
separate increments.
