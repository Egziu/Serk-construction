# ADR 0017: site operations and offline field capture

Status: accepted by the delivering team (2026-10-22); awaiting human review. Migration 0037. GATED-01.

## Context

Construction sites often have intermittent connectivity and electricity (master specification §3, LAW 05). Field staff need to record the day's work where it happens and synchronise later. LAW 05 sets the boundary: offline devices may prepare commands but never create authoritative financial state, and authoritative transactions are never CRDT-merged.

The first field record is the **daily site diary**: weather, notes, labour (trade, headcount, person-hours) and equipment (hours worked and idle). It is operational evidence for progress, delay and daywork claims. It posts nothing to the ledger.

## Decision

**Devices are registered and revocable.**
- A person registers their own device. The database requires a recent multi-factor login in the attestation.
- The server generates a 256-bit secret and returns it once. Only its SHA-256 is stored.
- A sync needs the person's bearer token **and** the device secret.
- The owner can revoke the device, and so can a `site.device.manage` holder (security administration).
- A revoked device row never changes again. Every later sync is refused, including commands queued before the revocation. The device clock does not count.

**The command log is the idempotency mechanism.**
- `site_sync_commands` is keyed by (device, client op id) and is append-only. A retried command is answered from the log and never applied twice. A retry with a different payload digest is refused.
- The device sequence only moves forward: a new command with an old sequence number is refused. The database moves the sequence only with a recorded command.
- Commands for one device are serialised by a lock on the device row. A revocation takes the same lock, so no command is recorded after the revocation commits.
- A command refused on its merits (validation, scope, a database rule) is still consumed: it is recorded with its reason and the sequence moves past it, so it is never applied later. A malformed envelope (bad op id, unknown kind, oversized payload, implausible client time) is refused without being recorded.

**Optimistic concurrency, no merge.**
- Every revision states the version it was based on, and only the author revises.
- If the server has a newer version, or the diary has left DRAFT, the answer is CONFLICT with the server's version and status. Nothing is merged.
- The client re-bases and sends a new command. Diaries are operational, so this goes further than LAW 05 strictly requires, but it avoids silent loss.

**Content is attested at every step.**
- Creation and each revision are attested (`site.diary.create`, `site.diary.revision.create`) by a deferred trigger at commit, after the lines are in place.
- Lines are versioned. They can be written only in the transaction that wrote the diary header, which is checked with `xmin`, so no line changes without the header's attestation. Old versions are kept as history.
- Submission (`site.diary.submit`) binds the submitted content. Approval and rejection (`site.diary.approve` / `.reject`) are human decisions by a different person, within the project's scope. They go through the 0035/0036 scope and session markers.

**The device clock is evidence, not authority.** The claimed client time is stored next to the server's receipt time. The server's date bounds the diary date: not in the future (one day of time-zone slack) and at most 60 days back. A client time more than a day ahead or 90 days behind is refused.

**One live diary per project and day.** A rejected diary frees the day.

## Consequences

- The web console records, submits and approves diaries, and registers and revokes devices. The native offline field app (Flutter/SQLite in the master specification) is **not built**. The sync API and its semantics are what it will use.
- Labour and equipment hours are recorded, but not yet costed. Equipment cost (GATED-03) and payroll will build on them.
- Photos and attachments are not supported. Document control (Gate E) will provide them.
- Not tested: real devices, real mobile networks, clock-skewed hardware, and very large offline queues. The batch is capped at 100 commands and 64 KiB per payload.

## Tests

- `TestOffline_DiaryLifecycleOnline`: versions, conflict, author-only revision, one diary per day, validation, segregation of duties, project scope, an AI principal refused, version history.
- `TestSync_IdempotencyConflictsAndRevocation`: replay, payload tampering under a reused op id, stale sequence, conflict and re-base, claimed client time kept, wrong secret, another person's device, revocation by the security administrator, audit of refusals.
- `TestSync_ConcurrentRetriesApplyOnce`: 8 concurrent retries of one command apply once. Two commands with the same sequence number cannot both apply. A revocation racing a sync leaves nothing recorded after it.
- `TestOffline_DatabaseRules`: 16 raw-SQL attempts with the tenant credential, all refused.
- `TestSync_APIDeviceDiaryApproval`: the HTTP API end to end, including step-up for registration and revoked sessions.
- `TestConsoleBrowserSite`: the browser journey, with an accessibility audit, phone width and dark theme.

## Addendum (2026-10-23, independent review 12, fixes inside 0037 before merge)

- **Attested log.** Every command-log row is attested by the device owner for that device and op id (`site.sync.create`). The server sets the last-sync time.
- **Sequence bound.** The sequence advances by at most 1000 per command.
- **Retries.** Only refusals on the merits are consumed. Temporary failures record nothing and return `retry`, and the rest of the batch waits, which keeps order.
- **Withdrawal and rejection of a DRAFT.** The author can cancel a DRAFT, and an approver can reject one, so no DRAFT can hold a project day indefinitely. The rejecting person is recorded in `rejected_by` and can never be the author.
- **Attestation timing.** Lines are written before the creation or revision attestation is consumed.
- **Device cap.** At most 5 active devices per person.
- **Canonical digest.** Payloads that repeat a key, including case-insensitively, are refused.
