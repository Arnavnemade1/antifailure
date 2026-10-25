---
title: Run recordings
description: Uploading each workflow's video, trace and screenshot to the control plane, so a failed run can be inspected after the machine that ran it is gone.
sidebar:
  order: 30
---

A run records a video, a Playwright trace and a screenshot for every workflow
it drives, under `.antifailure/artifacts/<environment>`. On a laptop those
files are there to open. On a CI runner they are deleted with the job, and the
person sent a link to a failed run gets a verdict with no way to see why.

When a run reports to a control plane and the organization has turned on
artifact storage, the engine uploads each workflow's recordings after the run
finishes. The run's page in the console lists them, with a link to open each
one.

## Turning it on

Storage is off for every organization until somebody turns it on. An owner or
an administrator does that in the console, under **Settings**, **Artifact
storage**, and chooses how many days to keep each file, from 1 to 365. The
default is 30. Every change is written to the audit log with the value it
replaced.

It is off by default because a recording shows whatever the application showed
the runner. Read
[run recordings on the trust boundary page](/docs/security/data-boundary#run-recordings-when-an-organization-turns-them-on)
before you turn it on. It says what a recording can hold and who can open one.

## What a run sends

One file of each kind per workflow:

| Kind | Types | Largest |
| --- | --- | --- |
| Video | WebM, MP4 | 64 MiB |
| Trace | Playwright trace, as a ZIP | 64 MiB |
| Screenshot | PNG, JPEG | 8 MiB |

A file is sent only if it is a regular file inside the environment's artifacts
directory once symlinks are resolved. A path that points anywhere else is
refused, even if the runner's report names it. A file over its limit is not
read. The engine sends the file's size and SHA-256 with it, and the control
plane refuses a body that matches neither, or one whose first bytes are not
the type it claims.

The run's report says what happened:

```text
uploaded 3 recording(s) for 1 workflow(s), 2.8 MB, to the control plane; the run's page in the console shows them
```

A file that was not sent gets a line of its own that says why. When storage is
off, the report says that once and sends nothing more.

## Keeping recordings on the machine

Set `AF_ARTIFACTS=local` and the engine sends no recordings, whatever the
organization decided:

```bash
AF_ARTIFACTS=local af test
```

Use it on a machine whose recordings must never leave it. The run's report says
the recordings stayed there and why.

## Opening one

Open the run in the console. The **Artifacts** card lists each file with its
workflow, size, digest and the date it expires. **Open** shows a video or a
screenshot in a new tab, and a video can be scrubbed. **Download** saves a
trace, named for its workflow. For a workflow called Sign in, open it with:

```bash
npx playwright show-trace "Sign in-trace.zip"
```

A member who can see the run's environment can open its recordings. A link to
another organization's artifact returns not found.

## How long they are kept

Each file gets its expiry when it is stored: the organization's retention, by
the database's clock. From that moment it is not served: opening it answers not
found, the same as a file that never existed, and the run's page lists it as
dropped, even if the housekeeping sweep has not reached it yet. The sweep then
deletes the bytes. The row stays and is listed as dropped, so the run's page
shows that a recording existed rather than looking as if none was made.

A new retention applies to files stored after the change. Files already kept
expire on the date they were stored with. Turning storage off stops new uploads
and leaves the files that are already kept until they expire.

## Limits

An organization keeps at most 256 MiB of recordings. An upload that would pass
that is refused, and the report says how much the organization holds. Space
comes back as kept files expire. The check and the write happen under one lock
per organization, so uploads from several runs at once cannot together keep
more than the quota. A self-hosted installation can change the quota with
`AF_ARTIFACT_ORG_QUOTA_MIB`; see the
[control plane reference](/docs/reference/control-plane).

One control plane process holds at most 128 MiB of uploads in memory at once.
When it is full it asks the engine to wait, and the engine retries. It also
retries when the control plane has not yet received the run's own events,
after sending any events it still holds. Each file gets four attempts. After two network failures in
a row the engine stops and leaves the rest on the machine.

## Where they are stored

In the control plane's Postgres database, in one megabyte chunks in the
`artifact_chunks` table. That has two consequences for a self-hosted
installation. A database backup includes the recordings, so plan backup storage
for up to 256 MiB per organization that turns this on, or for whatever
`AF_ARTIFACT_ORG_QUOTA_MIB` sets. Restoring a backup also
restores the recordings it held.

Each artifact row names the backend that holds its bytes, and the control plane
reads and writes through a store interface chosen by that name. Postgres is the
only backend today. An object store such as Azure Blob Storage can be added as a
second backend without moving the files already stored, because each row keeps
the name of the backend that holds it.

## What this does not do

It does not upload during a run. Recordings are sent after the run finishes, so
a run that is still going has none on its page yet.

It is not set per environment or per repository. The switch belongs to the
organization.

It does not reach a run that reports to no control plane. Those recordings stay
where they are, which is the ordinary case on a developer's machine.

Related: [the trust boundary](/docs/security/data-boundary),
[watching a run](/docs/guides/dashboard),
[workflows](/docs/guides/workflows).
