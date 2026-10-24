# added

A failed run's video, trace and screenshot can now be opened from the console.

The runner has always recorded them, into the environment's artifacts
directory, and nothing sent them anywhere. On a CI runner that directory goes
when the job does, so the person sent a link to a failed run had a verdict and
no way to see why. The run page's artifacts card was there, and empty.

When a run reports to a control plane and the organization has turned on
artifact storage, the engine now uploads each workflow's recordings after the
run finishes and emits `artifact.stored` for each one the control plane kept.
The run page lists them by workflow, with the date each expires and a link to
open a video or a screenshot in the browser or download a trace. Settings has
an Artifact storage card for the switch and the retention, 1 to 365 days with
30 as the default. `AF_ARTIFACTS=local` keeps a machine's recordings where they
are whatever the organization decided.

The bytes are kept in the control plane's Postgres database, behind a store
interface that each artifact row names, so an object store can be added as a
second backend later without moving the files already stored. See
[run recordings](/docs/guides/run-recordings).
