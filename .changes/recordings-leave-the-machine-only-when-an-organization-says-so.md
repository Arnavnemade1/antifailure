# security

Run recordings can now leave the machine that made them, and only when an
owner or an administrator turns that on.

A recording shows whatever the application showed the runner, so it is off for
every organization, including those that existed before this release. The
control plane refuses an upload before reading its body until the switch is on,
and every change to the switch or the retention is audited with what it
replaced.

A path is uploaded only if it resolves, symlinks included, to a regular file
inside the environment's artifacts directory, so a runner report that names a
file elsewhere cannot turn it into an upload. The control plane checks each
file's declared size, its SHA-256 and its first bytes against the type it
claims. The bytes are under the same row level security as every tenant table,
the operator's read role has its default read grant revoked on them, and the
sweeper that expires them can read only the columns it needs. A download needs
a signed-in member who can see the run's environment, answers another
organization's artifact as not found, and is served with a sandboxing
`Content-Security-Policy`, `nosniff` and `no-store`. A file past its expiry is answered
as not found from that moment, by the database's clock, rather than served
until the sweep removes its bytes, and deleting the organization deletes its
recordings. One organization may hold at most half of the memory a process
reserves for uploads arriving, and an upload that stalls or trickles is cut
off and gives that memory back, so one engine token cannot keep every other
organization's uploads refused as busy.

The trust boundary page now lists run recordings as opt in rather than as never
leaving the machine, and says what a recording can carry.
