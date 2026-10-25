-- The evidence nothing uploaded.
--
-- THE FAILURE THIS EXISTS FOR. The runner records a video, a Playwright trace
-- and a screenshot for every workflow it drives, into the environment's own
-- artifacts directory, and nothing ever moved them. 0001 built an `artifacts`
-- table, the console renders it on every run, and ingest accepts an
-- `artifact.stored` event, and none of the three had a writer: no storage
-- backend, no upload path and no download route. So a person sent a link to a
-- failed run saw the verdict and a table headed Artifacts that said nothing was
-- stored, and the evidence that would have shown them why was on a CI runner
-- that had already been thrown away.
--
-- WHAT THIS FILE ADDS, in four parts.
--
-- 1. The organization's choice, off by default. docs/security/data-boundary.md
--    told every reader that artifacts do not cross to the control plane, and
--    for a recording of somebody's application that was the right default. It
--    stays the default: uploads are refused for an organization that has not
--    turned them on, and turning them on is an audited act by somebody holding
--    organization.settings. The engine can also refuse on its own side with
--    AF_ARTIFACTS=local, for a machine that must never send one whatever its
--    organization decided.
--
-- 2. The columns an uploaded artifact needs that 0001 did not have: which
--    workflow it belongs to, which backend holds its bytes, and when it
--    expires. `storage_key` keeps its meaning, the locator inside whichever
--    backend `backend` names, so a second backend is a new value here and not
--    a migration of the rows already written.
--
-- 3. The first backend, which is this database. 0001 says the bytes belong in
--    object storage and are fetched with a signed URL, and that is still the
--    destination: the control plane holds an ArtifactStore interface and the
--    download route is written so a backend can answer with a redirect. Postgres
--    is the first implementation because it is the one store every
--    installation already has, self hosted included, and needs no new
--    infrastructure to be created before the code works. Bytes are held in one
--    megabyte chunks so that no request ever holds a whole video in memory and
--    no value approaches the limits on a single bytea.
--
-- 4. Retention that actually runs. security.ts said there was no retention
--    policy anywhere and that artifacts carry a single retained flag. An
--    artifact now carries its expiry from the moment it is written, from the
--    organization's retention setting, and the expiry sweeper removes the bytes
--    and clears `retained` when the database's own clock passes it. The row
--    stays, so a run still says what it had.

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. The organization's choice
-- ---------------------------------------------------------------------------

ALTER TABLE organizations
  -- Off until somebody turns it on. The default is the promise the data
  -- boundary page has always made, and an organization that never visits the
  -- setting keeps it.
  ADD COLUMN artifact_uploads_enabled boolean NOT NULL DEFAULT false,
  -- How long an uploaded artifact is kept, in days. Thirty because a run is
  -- read in the week its pull request is open, and the recordings of a run
  -- from last quarter are evidence about code that no longer exists. Bounded
  -- because a retention that never ends is not a retention.
  ADD COLUMN artifact_retention_days integer NOT NULL DEFAULT 30,
  ADD CONSTRAINT organizations_artifact_retention_is_bounded
    CHECK (artifact_retention_days BETWEEN 1 AND 365);

-- ---------------------------------------------------------------------------
-- 2. What an uploaded artifact records
-- ---------------------------------------------------------------------------

ALTER TABLE artifacts
  -- The workflow whose evidence this is. Empty for a row written before this
  -- column existed, which is a row a fixture wrote, because nothing else ever
  -- wrote one. Not null, so that "one video per workflow per run" is a unique
  -- index rather than a promise.
  ADD COLUMN workflow text NOT NULL DEFAULT '',
  -- Which ArtifactStore holds the bytes, and therefore how `storage_key` is
  -- read. A short identifier rather than an enum, so the second backend is a
  -- value and not an ALTER TYPE.
  ADD COLUMN backend text NOT NULL DEFAULT 'postgres',
  -- When the bytes are due to be removed. Null for a row written before this
  -- column, which nothing sweeps, and for a row whose bytes were never stored.
  ADD COLUMN expires_at timestamptz,
  ADD CONSTRAINT artifacts_backend_is_an_identifier
    CHECK (backend ~ '^[a-z][a-z0-9_]{0,31}$'),
  ADD CONSTRAINT artifacts_workflow_is_bounded
    CHECK (char_length(workflow) <= 500);

-- One artifact of a kind per workflow per step per run. A retry of an upload
-- that already landed finds this row and is answered with it, and a second,
-- different video for the same workflow is refused rather than stacked beside
-- the first where nothing could say which one the verdict was about.
--
-- The step is part of it because 0001 gave a run one screenshot per step, and
-- the staging fixture writes exactly that. A workflow's own evidence carries
-- no step, and the COALESCE makes those rows one slot rather than letting
-- every NULL count as distinct, which is what a plain unique index would do
-- and would enforce nothing for the case that matters.
CREATE UNIQUE INDEX artifacts_one_kind_per_workflow_step
  ON artifacts (run_id, workflow, kind, COALESCE(step, -1));

-- The sweeper's work list, and nothing else's. Partial, so it is the size of
-- what is due rather than of every artifact ever recorded.
CREATE INDEX artifacts_due_to_expire
  ON artifacts (expires_at) WHERE retained AND expires_at IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 3. The bytes, in this database
-- ---------------------------------------------------------------------------

CREATE TABLE artifact_chunks (
  org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  artifact_id  uuid NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
  seq          integer NOT NULL,
  bytes        bytea NOT NULL,
  -- The artifact's expiry, copied here so the sweeper's policy on this table
  -- reads a column of the row it is deleting rather than reaching through to
  -- artifacts, which it can see only a few columns of.
  expires_at   timestamptz,
  PRIMARY KEY (artifact_id, seq),
  CONSTRAINT artifact_chunks_seq_is_natural CHECK (seq >= 0),
  -- A megabyte at most, and never empty. The store writes exactly this size
  -- except for the last chunk, and an empty chunk is a write that went wrong.
  CONSTRAINT artifact_chunks_are_bounded
    CHECK (octet_length(bytes) BETWEEN 1 AND 1048576)
);

-- Stored out of line and uncompressed. A video, a trace archive and a PNG are
-- all compressed already, so the default would spend CPU on every write to
-- save nothing.
ALTER TABLE artifact_chunks ALTER COLUMN bytes SET STORAGE EXTERNAL;

-- The application reads, writes and deletes chunks of its own tenant. Not
-- UPDATE: a chunk is written once, and an artifact whose bytes changed after
-- their digest was recorded is the one thing the digest exists to rule out.
GRANT SELECT, INSERT, DELETE ON artifact_chunks TO antifailure_app;

-- Withheld from the operator, which is the one table in the schema that is.
--
-- 0023 grants antifailure_admin SELECT on every table, and sets the default
-- privileges so every later table is granted the same at the moment it is
-- created, this one included. That is right for the operator portal, which
-- reads every tenant's metadata and needs to, and it is wrong here: these rows
-- are recordings of customers' applications, and a role with BYPASSRLS that
-- can read them can read all of them at once. The portal reads the artifact
-- index, which stays granted; nothing it shows needs a byte of this table.
--
-- Found by the assertion at the end of this file on its first run, which is
-- what it is there for.
REVOKE ALL ON artifact_chunks FROM antifailure_admin;

ALTER TABLE artifact_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifact_chunks FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON artifact_chunks
  FOR ALL TO antifailure_app
  USING (org_id = current_org())
  WITH CHECK (org_id = current_org());

-- ---------------------------------------------------------------------------
-- 4. Retention
-- ---------------------------------------------------------------------------
--
-- The expiry sweep enters antifailure_sweeper for one transaction, which is
-- the mechanism 0024 built and 0041 extended, and for the reason those files
-- give: a sweep is nobody's request, so it arrives with no tenant, and a policy
-- on antifailure_app admitting a tenantless caller would be OR'd into every
-- other policy on the table. Policies attach to roles, so these two admit the
-- sweeper and nobody else.
--
-- The row restriction is the database's clock, never a value the application
-- passes in, so a sweeper with a wrong idea of the time removes nothing early.

GRANT SELECT (id, backend, storage_key, expires_at, retained), UPDATE (retained)
  ON artifacts TO antifailure_sweeper;

-- Two policies rather than one FOR ALL, and the split is load bearing. An
-- UPDATE whose WHERE reads a column needs SELECT rights, so Postgres holds the
-- row it writes to the SELECT policy as well as the row it reads. A single
-- policy requiring `retained` therefore refused the very update that clears
-- it: "new row violates row-level security policy", on the first run of the
-- sweep test. So the sweeper may SEE an expired row whatever its flag says,
-- and may only UPDATE one that is still retained, into one that is not.
CREATE POLICY sweep_sees_expired_artifacts ON artifacts
  FOR SELECT TO antifailure_sweeper
  USING (expires_at <= now());
CREATE POLICY sweep_expires_artifacts ON artifacts
  FOR UPDATE TO antifailure_sweeper
  USING (retained AND expires_at <= now())
  WITH CHECK (NOT retained AND expires_at <= now());

GRANT SELECT (artifact_id, expires_at), DELETE ON artifact_chunks TO antifailure_sweeper;
CREATE POLICY sweep_expired_artifact_chunks ON artifact_chunks
  FOR ALL TO antifailure_sweeper
  USING (expires_at <= now());

-- What the two grants above must not have given, checked rather than hoped.
DO $$
BEGIN
  IF has_column_privilege('antifailure_sweeper', 'artifact_chunks', 'bytes', 'SELECT') THEN
    RAISE EXCEPTION 'antifailure_sweeper can read artifact_chunks.bytes';
  END IF;
  IF has_column_privilege('antifailure_sweeper', 'artifacts', 'org_id', 'SELECT') THEN
    RAISE EXCEPTION 'antifailure_sweeper can read artifacts.org_id';
  END IF;
  IF has_column_privilege('antifailure_sweeper', 'artifacts', 'run_id', 'SELECT') THEN
    RAISE EXCEPTION 'antifailure_sweeper can read artifacts.run_id';
  END IF;
  IF has_table_privilege('antifailure_sweeper', 'artifacts', 'DELETE') THEN
    RAISE EXCEPTION 'antifailure_sweeper can delete artifacts, and the row is what says a run had one';
  END IF;
  -- The operator role reads the artifact index for the operator portal. It
  -- must not read the recordings themselves, which are a customer's
  -- application on the screen, and BYPASSRLS would let it read every
  -- tenant's at once.
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'antifailure_admin')
     AND has_table_privilege('antifailure_admin', 'artifact_chunks', 'SELECT') THEN
    RAISE EXCEPTION 'antifailure_admin can read artifact_chunks';
  END IF;
END
$$;

COMMIT;
