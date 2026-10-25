// The two routes that move an artifact: the engine uploading one, and a member
// opening one from the console.
//
// UPLOAD. POST /v1/environments/:envId/runs/:runId/artifacts, with an engine
// token, the bytes as the body, and what they are in headers. Everything that
// can be refused without reading the body is refused first, in this order:
// the token, the organization's plan and suspension, the declaration, then
// one short read of the organization's choice, the run, an existing artifact
// and the quota. Only then is the body read, into memory reserved before the
// first byte arrives, and the bytes are checked against the digest and the
// signature of the declared type before one row is written. The row and its
// bytes are then written in one transaction, so a failure leaves neither.
//
// The body is held in memory rather than streamed into the database. A
// transaction open for as long as a CI runner takes to send sixty four
// megabytes would hold one of the pool's ten connections for that long, and
// the uploads in flight would be the control plane. Memory is bounded instead,
// per process, by the budget below.
//
// DOWNLOAD. GET /v1/artifacts/:id, with the console's session, for a member
// whose role grants environments.view on the run's environment. The bytes come
// from the store that wrote them, streamed, with ranges, so a video seeks; or
// the browser is sent to a URL the store minted, for a store that can.

import { randomUUID, createHash } from 'node:crypto'
import type { Context, Hono, Env } from 'hono'
import { sql, type Db, type Pool } from '@antifailure/db'
import type { Clock } from '../clock.ts'
import { authenticateEngine, runRowFor, suspensionReason } from '../ingest.ts'
import { HOSTED_ACCESS_MESSAGE, hasHostedAccess, type HostedRequiredPlan } from '../hosted.ts'
import { readCookie, resolveSession, SESSION_COOKIE } from '../auth/session.ts'
import { permits } from '../permissions.ts'
import {
  ArtifactRefusal, KIND_POLICIES, bytesMatchType, contentDisposition, isArtifactKind,
  parseRange, readDeclaration, type UploadDeclaration,
} from './policy.ts'
import type { ArtifactStores } from './store.ts'

const MIB = 1024 * 1024

/**
 * The default for how much one organization may keep, retained, at once.
 *
 * 256 MiB, because the bytes live in the control plane's own database, which
 * every organization shares. Production's is 64 GiB (database_storage_mb in
 * production.tfvars), and at the 2 GiB this started at, thirty two
 * organizations turning storage on would have filled it, with the runs,
 * events and audit log of every other organization in the same volume. At
 * 256 MiB that is two hundred and fifty six, and a run that fails keeps a
 * video, a trace and a screenshot per failed workflow, a few megabytes each,
 * so it is still dozens of failed runs per organization inside a thirty day
 * retention. AF_ARTIFACT_ORG_QUOTA_MIB changes it for an installation whose
 * database is sized for more; see artifactQuotaBytesFrom.
 */
export const DEFAULT_ORG_QUOTA_BYTES = 256 * MIB

/** The largest quota AF_ARTIFACT_ORG_QUOTA_MIB may set, which is a terabyte. */
export const MAX_ORG_QUOTA_MIB = 1024 * 1024

/**
 * The default for how many upload bytes one process holds at once.
 *
 * 128 MiB. A body is held once, in the one buffer readExactly allocates at its
 * declared length, and the store writes it a megabyte at a time, so an upload
 * costs its own size plus a few megabytes of encoding while a chunk is on the
 * wire. 128 MiB is two of the largest kind, a 64 MiB video or trace, at once,
 * and an eighth of the 1 GiB a control plane container is given (app_memory),
 * which leaves the rest for the V8 heap, the connection pools and every other
 * request the process is serving. It was 192 MiB, which was a fifth of the
 * container spent on one feature. It is also half of what one organization
 * may keep at all, so the budget, not the quota, is never what makes an
 * organization's normal burst after a run wait.
 */
export const DEFAULT_IN_FLIGHT_BYTES = 128 * MIB

/**
 * The organization quota from AF_ARTIFACT_ORG_QUOTA_MIB, in bytes.
 *
 * Unset or blank is the default. Anything else must be a whole number of MiB
 * from 1 to MAX_ORG_QUOTA_MIB, and a value that is not stops the process at
 * startup, the way AF_TRUSTED_PROXY_HOPS does: a quota misread as zero refuses
 * every upload, and one misread as unbounded lets one organization fill the
 * database, and neither should be discovered by a customer.
 */
export function artifactQuotaBytesFrom(value: string | undefined | null): number {
  const raw = value?.trim()
  if (!raw) return DEFAULT_ORG_QUOTA_BYTES
  const refuse = () => new Error(
    `AF_ARTIFACT_ORG_QUOTA_MIB must be a whole number of MiB from 1 to ${MAX_ORG_QUOTA_MIB}; ` +
    `received ${JSON.stringify(value)}.`)
  if (!/^\d{1,7}$/.test(raw)) throw refuse()
  const mib = Number(raw)
  if (mib < 1 || mib > MAX_ORG_QUOTA_MIB) throw refuse()
  return mib * MIB
}

/** What the process says about the quota at startup, so it is never a guess. */
export function describeArtifactQuota(bytes: number): string {
  const mib = Math.round(bytes / MIB)
  return bytes === DEFAULT_ORG_QUOTA_BYTES
    ? `each organization may keep ${mib} MiB of run artifacts (AF_ARTIFACT_ORG_QUOTA_MIB is not set)`
    : `each organization may keep ${mib} MiB of run artifacts (AF_ARTIFACT_ORG_QUOTA_MIB=${mib})`
}

/**
 * The default for how many upload bytes ONE organization holds at once, in
 * any one process.
 *
 * The process budget alone was a resource every tenant shared and any one of
 * them could take: a reservation is the declared length, made before a byte
 * arrives, so an engine token that opened two uploads declaring 64 MiB each
 * and sent nothing held the whole 128 MiB, and every other organization's
 * upload was refused as busy until the body deadline let go. This is one
 * reservation of the largest kind, half the process budget, so a single
 * organization can never hold more than its share, and a second organization
 * always finds room.
 */
export const DEFAULT_ORG_IN_FLIGHT_BYTES = 64 * MIB

/** How long a body may take to arrive once reading has started, in total. */
export const DEFAULT_BODY_DEADLINE_MS = 5 * 60 * 1000

/**
 * How long a body may go without a single byte arriving.
 *
 * The total deadline alone let a client that sent three bytes and stopped
 * keep its reservation for the full five minutes. Fifteen seconds is far
 * longer than any pause a CI runner's upload has, and short enough that a
 * stalled one gives its memory back promptly.
 */
export const DEFAULT_BODY_IDLE_MS = 15 * 1000

/**
 * The slowest a body may arrive on average, after the grace period below.
 *
 * The idle timeout alone is defeated by one byte every fourteen seconds. 256
 * KiB a second is two megabits, which a CI runner exceeds by orders of
 * magnitude, and at which the largest artifact arrives in about four and a
 * quarter minutes, inside the total deadline.
 */
export const DEFAULT_BODY_MIN_BYTES_PER_SECOND = 256 * 1024

/** How long a body gets before the minimum rate applies, for a slow start. */
export const DEFAULT_BODY_GRACE_MS = 10 * 1000

/** How a body must keep arriving once it has started. */
export interface BodyPace {
  /** The longest gap between two pieces of the body. */
  idleMs: number
  /** The slowest average rate, measured from the start once graceMs has passed. */
  minBytesPerSecond: number
  /** How long before the average rate is enforced. */
  graceMs: number
}

export const DEFAULT_BODY_PACE: BodyPace = {
  idleMs: DEFAULT_BODY_IDLE_MS,
  minBytesPerSecond: DEFAULT_BODY_MIN_BYTES_PER_SECOND,
  graceMs: DEFAULT_BODY_GRACE_MS,
}

export interface ArtifactRouteOptions {
  pool: Pool
  clock: Clock
  stores: ArtifactStores
  /** The plan a hosted organization needs, or null when there is no gate. */
  hostedRequiredPlan: HostedRequiredPlan | null
  /** How many retained bytes an organization may hold. */
  orgQuotaBytes?: number
  /** How many upload bytes this process may hold in memory at once. */
  inFlightBytes?: number
  /** How many of those one organization may hold. */
  orgInFlightBytes?: number
  /** How long a body may take to arrive. */
  bodyDeadlineMs?: number
  /** How a body must keep arriving: the idle gap and the minimum rate. */
  bodyPace?: BodyPace
}

/**
 * Memory reserved for upload bodies, per process.
 *
 * Reserved by the declared length before a byte is read, so the sum of bodies
 * in memory can never exceed it, whatever order they arrive in. A request that
 * does not fit is told to come back rather than queued, because a queue here
 * is a connection held open on a server that has already decided it is busy.
 */
export class ByteBudget {
  private used = 0
  readonly capacity: number
  constructor(capacity: number) {
    this.capacity = capacity
  }
  reserve(bytes: number): boolean {
    if (bytes > this.capacity || this.used + bytes > this.capacity) return false
    this.used += bytes
    return true
  }
  release(bytes: number): void {
    this.used = Math.max(0, this.used - bytes)
  }
  get inUse(): number {
    return this.used
  }
}

/**
 * The same budget, one per organization, for the share of the process budget
 * one tenant may hold. An organization with nothing in flight has no entry, so
 * the map is the size of what is arriving rather than of every tenant seen.
 */
export class OrgByteBudgets {
  private readonly used = new Map<string, number>()
  readonly capacity: number
  constructor(capacity: number) {
    this.capacity = capacity
  }
  reserve(orgId: string, bytes: number): boolean {
    const now = this.used.get(orgId) ?? 0
    if (bytes > this.capacity || now + bytes > this.capacity) return false
    this.used.set(orgId, now + bytes)
    return true
  }
  release(orgId: string, bytes: number): void {
    const left = (this.used.get(orgId) ?? 0) - bytes
    if (left > 0) this.used.set(orgId, left)
    else this.used.delete(orgId)
  }
  inUse(orgId: string): number {
    return this.used.get(orgId) ?? 0
  }
}

/**
 * Reads exactly `declared` bytes, or refuses.
 *
 * A body longer than it said is cut off at the first byte past the declaration,
 * and one shorter is refused once it ends, because the digest the engine sent
 * is of the length it declared and a different length is a different file.
 */
export async function readExactly(
  request: Request, declared: number, deadlineMs: number, pace: BodyPace = DEFAULT_BODY_PACE,
): Promise<Buffer> {
  if (!request.body) throw new ArtifactRefusal(400, 'length', 'The upload has no body.')
  const reader = request.body.getReader()
  const out = Buffer.allocUnsafe(declared)
  let received = 0
  let stopped: string | null = null
  const stop = (why: string) => {
    if (stopped !== null) return
    stopped = why
    void reader.cancel(why).catch(() => {})
  }
  const timer = setTimeout(() => stop(
    `The body did not arrive within ${Math.round(deadlineMs / 1000)} seconds.`), deadlineMs)
  // The pace is checked on a tick rather than on each piece, because a client
  // that has stopped sending produces no piece to check it on.
  const started = Date.now()
  let lastByteAt = started
  const pacer = setInterval(() => {
    const now = Date.now()
    if (now - lastByteAt > pace.idleMs) {
      stop(`No part of the body arrived for ${Math.round(pace.idleMs / 1000)} seconds.`)
      return
    }
    const elapsed = now - started
    if (elapsed > pace.graceMs && received < (pace.minBytesPerSecond * (elapsed - pace.graceMs)) / 1000) {
      stop(`The body arrived more slowly than ${Math.round(pace.minBytesPerSecond / 1024)} KiB a second.`)
    }
  }, Math.max(10, Math.min(1000, Math.floor(pace.idleMs / 4))))
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      if (received + value.byteLength > declared) {
        await reader.cancel().catch(() => {})
        throw new ArtifactRefusal(400, 'length', `The body is longer than the declared ${declared} bytes.`)
      }
      out.set(value, received)
      received += value.byteLength
      lastByteAt = Date.now()
    }
  } catch (err) {
    if (err instanceof ArtifactRefusal) throw err
    throw new ArtifactRefusal(400, 'length', 'The body ended before it was complete.')
  } finally {
    clearTimeout(timer)
    clearInterval(pacer)
    reader.releaseLock()
  }
  // A cancelled read resolves as the end of the body rather than rejecting,
  // so a body stopped by the pace or the deadline arrives here, and is named
  // for why it stopped rather than for being short.
  if (stopped !== null) throw new ArtifactRefusal(400, 'too_slow', stopped)
  if (received !== declared) {
    throw new ArtifactRefusal(
      400, 'length', `The body is ${received} bytes and Content-Length declared ${declared}.`,
    )
  }
  return out
}

/** What an artifact row says about itself in a response. */
interface ArtifactRecord {
  id: string
  kind: string
  workflow: string
  step: number | null
  content_type: string | null
  size_bytes: number
  sha256: string | null
  expires_at: string | null
}

function describe(row: {
  id: string; kind: string; workflow: string; step: number | null; content_type: string | null
  size_bytes: string | number | null; sha256: string | null; expires_at: Date | string | null
}): ArtifactRecord {
  return {
    id: row.id,
    kind: row.kind,
    workflow: row.workflow,
    step: row.step,
    content_type: row.content_type,
    size_bytes: Number(row.size_bytes ?? 0),
    sha256: row.sha256,
    expires_at: row.expires_at === null ? null : new Date(row.expires_at).toISOString(),
  }
}

/** The JSON body a refusal is answered with. */
/**
 * The refusal for an organization whose kept artifacts would pass its quota.
 *
 * Both checks, the one before the body and the one under the lock, say the
 * same sentence, and the engine repeats it to a person, so the sizes are
 * written the way a person reads them. It does not suggest shortening the
 * retention: a new retention applies to files stored after it, so the room
 * comes back only as the files already kept expire.
 */
function quotaRefusal(quota: number, used: number): ArtifactRefusal {
  const mib = (n: number) => `${(n / (1024 * 1024)).toFixed(n < 10 * 1024 * 1024 ? 1 : 0)} MiB`
  return new ArtifactRefusal(507, 'quota',
    `This organization keeps at most ${mib(quota)} of artifacts and holds ${mib(used)}. Room comes ` +
    'back as kept artifacts expire.')
}

function refusalBody(err: ArtifactRefusal) {
  return {
    error: err.message,
    code: err.code,
    ...(err.retryAfterSeconds === null ? {} : { retryAfterSeconds: err.retryAfterSeconds }),
  }
}

export function mountArtifacts<E extends Env>(app: Hono<E>, options: ArtifactRouteOptions): void {
  const { pool, clock, stores } = options
  const quota = options.orgQuotaBytes ?? DEFAULT_ORG_QUOTA_BYTES
  const budget = new ByteBudget(options.inFlightBytes ?? DEFAULT_IN_FLIGHT_BYTES)
  const orgBudgets = new OrgByteBudgets(options.orgInFlightBytes ?? DEFAULT_ORG_IN_FLIGHT_BYTES)
  const deadlineMs = options.bodyDeadlineMs ?? DEFAULT_BODY_DEADLINE_MS
  const pace = options.bodyPace ?? DEFAULT_BODY_PACE

  const refuse = (c: Context<E>, err: ArtifactRefusal) => {
    if (err.retryAfterSeconds !== null) c.header('retry-after', String(err.retryAfterSeconds))
    return c.json(refusalBody(err), err.status)
  }

  app.post('/v1/environments/:envId/runs/:runId/artifacts', async (c) => {
    c.header('cache-control', 'no-store')
    const auth = c.req.header('authorization') ?? ''
    const engine = await authenticateEngine(pool, clock, auth.startsWith('Bearer ') ? auth.slice(7).trim() : '')
    // The same answers, in the same order, as every other engine route.
    if (!engine) return c.json({ error: 'This token is not valid.' }, 401)
    if (!hasHostedAccess(engine.plan, options.hostedRequiredPlan)) {
      return c.json({ error: HOSTED_ACCESS_MESSAGE }, 402)
    }
    const suspended = await suspensionReason(pool, engine.orgId)
    if (suspended !== null) {
      return refuse(c, new ArtifactRefusal(403, 'suspended',
        `This organization is suspended: ${suspended}`, 300))
    }

    const envId = c.req.param('envId')
    const runId = c.req.param('runId')
    if (!envId || envId.length > 200 || !runId || runId.length > 200) {
      return refuse(c, new ArtifactRefusal(400, 'run', 'The path must name an environment and a run.'))
    }

    let declared: UploadDeclaration
    try {
      declared = readDeclaration((name) => c.req.header(name))
    } catch (err) {
      if (err instanceof ArtifactRefusal) return refuse(c, err)
      throw err
    }

    const runRow = runRowFor(engine.orgId, envId, runId)
    const stepKey = declared.step ?? -1
    const tenant = { orgId: engine.orgId }

    // Everything that can refuse, before a byte of the body is read.
    let before: { existing: ArtifactRecord | null; retentionDays: number }
    try {
      before = await pool.withTenant(tenant, async (db) => {
        const org = await db.execute<{
          enabled: boolean; retention_days: number; used: string; run_exists: boolean
        }>(sql`
          SELECT o.artifact_uploads_enabled AS enabled,
                 o.artifact_retention_days AS retention_days,
                 (SELECT coalesce(sum(a.size_bytes), 0) FROM artifacts a WHERE a.retained)::text AS used,
                 EXISTS (SELECT 1 FROM runs r WHERE r.id = ${runRow}::uuid) AS run_exists
          FROM organizations o WHERE o.id = ${engine.orgId}::uuid`)
        const row = org[0]
        if (!row || !row.enabled) {
          throw new ArtifactRefusal(403, 'uploads_disabled',
            'This organization has not turned on artifact storage, so the recordings stay where the ' +
            'run happened. An administrator can turn it on under Settings, Artifacts.')
        }
        if (!row.run_exists) {
          // The run's own events are what create its row, and they are sent
          // before its artifacts. An upload that overtook them is told to
          // wait for them rather than refused for good.
          throw new ArtifactRefusal(409, 'run_not_recorded',
            `The control plane has no record of run ${runId} in ${envId} yet. Its events may still be ` +
            'on their way; retry once they have been delivered.', 5)
        }
        const existing = await db.execute<{
          id: string; kind: string; workflow: string; step: number | null; content_type: string | null
          size_bytes: string | null; sha256: string | null; expires_at: Date | string | null; retained: boolean
        }>(sql`
          SELECT id, kind, workflow, step, content_type, size_bytes::text AS size_bytes, sha256,
                 expires_at, retained
          FROM artifacts
          WHERE run_id = ${runRow}::uuid AND workflow = ${declared.workflow}
            AND kind = ${declared.kind} AND COALESCE(step, -1) = ${stepKey}`)
        const found = existing[0]
        if (found) {
          if (found.sha256 === declared.sha256 && found.retained) {
            return { existing: describe(found), retentionDays: row.retention_days }
          }
          throw new ArtifactRefusal(409, 'artifact_exists',
            `This run already holds a ${declared.kind} for ${declared.workflow}, and it is a different ` +
            'file. A run keeps one of each kind per workflow, so the first one stands.')
        }
        if (Number(row.used) + declared.sizeBytes > quota) {
          throw quotaRefusal(quota, Number(row.used))
        }
        return { existing: null, retentionDays: row.retention_days }
      })
    } catch (err) {
      if (err instanceof ArtifactRefusal) return refuse(c, err)
      throw err
    }

    if (before.existing) {
      // A retry of an upload that already landed. Answered without reading
      // the body, with the row it made the first time.
      return c.json({ ...before.existing, created: false }, 200)
    }

    // The organization's share first, then the process's, so that one
    // tenant's uploads are refused by its own cap before they can reach the
    // budget every tenant shares. Both are released in the finally below,
    // which every exit reaches: a refusal, a stalled or slow body cut off by
    // the pace, a client that disconnects (the read then rejects), and a
    // throw from the database.
    if (!orgBudgets.reserve(engine.orgId, declared.sizeBytes)) {
      return refuse(c, new ArtifactRefusal(429, 'busy',
        'This organization already has as many artifacts arriving as one organization may send at ' +
        'once. Try again shortly.', 10))
    }
    if (!budget.reserve(declared.sizeBytes)) {
      orgBudgets.release(engine.orgId, declared.sizeBytes)
      return refuse(c, new ArtifactRefusal(429, 'busy',
        'This server is already receiving as many artifacts as it holds at once. Try again shortly.', 10))
    }
    try {
      const bytes = await readExactly(c.req.raw, declared.sizeBytes, deadlineMs, pace)
      const digest = createHash('sha256').update(bytes).digest('hex')
      if (digest !== declared.sha256) {
        throw new ArtifactRefusal(422, 'digest_mismatch',
          'The body does not match x-artifact-sha256, so it is not the file the engine meant to send.')
      }
      if (!bytesMatchType(bytes, declared.contentType)) {
        throw new ArtifactRefusal(415, 'content_mismatch',
          `The body does not begin the way a ${declared.contentType} file does, so it is not stored as one.`)
      }

      const now = clock.now()
      const record = await pool.withTenant(tenant, async (db) => {
        // One upload per ORGANIZATION at a time from here to the commit, so
        // that the quota read below and the insert that spends it are one step
        // for every upload that could spend the same quota. This was a lock per
        // run, which kept two retries of one file from both writing, and let
        // two uploads for two different runs of one organization both read the
        // same total, both pass, and together keep up to twice the quota. A
        // lock per organization covers both cases, since a run belongs to one
        // organization, and it is the only lock taken here, so there is no
        // second one to acquire in a different order.
        //
        // It is held while the chunks are written, which serializes one
        // organization's writes and nobody else's. That is the point rather
        // than a cost: a write it lets through concurrently is one the quota
        // did not see.
        await db.execute(sql`SELECT pg_advisory_xact_lock(hashtextextended(${'artifact-org:' + engine.orgId}, 0))`)
        const again = await db.execute<{
          id: string; kind: string; workflow: string; step: number | null; content_type: string | null
          size_bytes: string | null; sha256: string | null; expires_at: Date | string | null
          retained: boolean
        }>(sql`
          SELECT id, kind, workflow, step, content_type, size_bytes::text AS size_bytes, sha256,
                 expires_at, retained
          FROM artifacts
          WHERE run_id = ${runRow}::uuid AND workflow = ${declared.workflow}
            AND kind = ${declared.kind} AND COALESCE(step, -1) = ${stepKey}`)
        if (again[0]) {
          if (again[0].sha256 === declared.sha256 && again[0].retained) {
            return { ...describe(again[0]), created: false }
          }
          throw new ArtifactRefusal(409, 'artifact_exists',
            `This run already holds a ${declared.kind} for ${declared.workflow}, and it is a different file.`)
        }
        const settings = await db.execute<{ enabled: boolean; used: string }>(sql`
          SELECT o.artifact_uploads_enabled AS enabled,
                 (SELECT coalesce(sum(a.size_bytes), 0) FROM artifacts a WHERE a.retained)::text AS used
          FROM organizations o WHERE o.id = ${engine.orgId}::uuid`)
        // Asked again, because the body took time and the answer can change in
        // it: an administrator who turns storage off while a file is arriving
        // has said no to that file too.
        if (!settings[0]?.enabled) {
          throw new ArtifactRefusal(403, 'uploads_disabled',
            'This organization turned artifact storage off while this upload was arriving.')
        }
        if (Number(settings[0].used) + bytes.byteLength > quota) {
          throw quotaRefusal(quota, Number(settings[0].used))
        }

        const id = randomUUID()
        const writer = stores.writer
        // The row first, so the chunks' foreign key has something to name, in
        // the same transaction, so neither survives without the other.
        //
        // The expiry is the DATABASE's clock plus the retention, never this
        // process's. The sweeper's policy decides on the database's now(), as
        // 0052 requires, and an expiry computed on a second clock is one the
        // two can disagree about: a test server whose clock is fixed in the
        // past wrote expiries that were already behind the database, and the
        // sweep removed a video seconds after it was stored.
        const inserted = await db.execute<{ expires_at: Date | string }>(sql`
          INSERT INTO artifacts (
            id, org_id, run_id, kind, step, workflow, storage_key, backend, content_type,
            size_bytes, sha256, retained, expires_at, created_at)
          VALUES (
            ${id}::uuid, ${engine.orgId}::uuid, ${runRow}::uuid, ${declared.kind}, ${declared.step},
            ${declared.workflow}, ${'pending:' + id}, ${writer.backend}, ${declared.contentType},
            ${bytes.byteLength}, ${digest}, true,
            now() + make_interval(days => ${before.retentionDays}),
            ${now.toISOString()}::timestamptz)
          RETURNING expires_at`)
        const expiresAt = new Date(inserted[0]!.expires_at)
        const stored = await writer.put(db, { orgId: engine.orgId, artifactId: id, expiresAt }, bytes)
        await db.execute(sql`UPDATE artifacts SET storage_key = ${stored.locator} WHERE id = ${id}::uuid`)
        return {
          id, kind: declared.kind, workflow: declared.workflow, step: declared.step,
          content_type: declared.contentType, size_bytes: bytes.byteLength, sha256: digest,
          expires_at: expiresAt.toISOString(), created: true,
        }
      })
      return c.json(record, record.created ? 201 : 200)
    } catch (err) {
      if (err instanceof ArtifactRefusal) return refuse(c, err)
      throw err
    } finally {
      budget.release(declared.sizeBytes)
      orgBudgets.release(engine.orgId, declared.sizeBytes)
    }
  })

  const download = async (c: Context<E>) => {
    c.header('cache-control', 'private, no-store')
    c.header('referrer-policy', 'no-referrer')
    c.header('x-content-type-options', 'nosniff')
    c.header('cross-origin-resource-policy', 'same-origin')
    // Opened on its own, the response is a document with no permission to do
    // anything. Embedded in the console, it is a video or an image, and the
    // console's own policy decides what that may do.
    c.header('content-security-policy', "default-src 'none'; sandbox")

    const token = readCookie(c.req.header('cookie'), SESSION_COOKIE)
    const session = token ? await resolveSession(pool, clock, token) : null
    if (!session) return c.json({ error: 'Sign in first.' }, 401)
    if (!session.orgId || !session.role) {
      return c.json({ error: 'You are not a member of an organization.' }, 403)
    }

    const id = c.req.param('id') ?? ''
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
      return c.json({ error: 'That is not an artifact identifier.' }, 400)
    }
    const tenant = { orgId: session.orgId, userId: session.userId }
    const rows = await pool.withTenant(tenant, async (db) =>
      db.execute<{
        id: string; org_id: string; kind: string; workflow: string; content_type: string | null
        size_bytes: string | null; storage_key: string; backend: string; retained: boolean
        env_id: string | null
      }>(sql`
        SELECT a.id, a.org_id, a.kind, a.workflow, a.content_type, a.size_bytes::text AS size_bytes,
               a.storage_key, a.backend, a.retained, e.env_id
        FROM artifacts a
        JOIN runs r ON r.id = a.run_id
        LEFT JOIN environments e ON e.id = r.environment_id
        WHERE a.id = ${id}::uuid
          -- Past its expiry is gone, whether or not the sweep has reached it
          -- yet. The sweep runs on an interval, and before this a file was
          -- served for as long as that interval left it on disk, past the date
          -- the organization was told it would be removed. Read by the
          -- database's clock, the one the sweep's own policy reads, so the
          -- two can never disagree about whether a file has expired.
          AND (a.expires_at IS NULL OR a.expires_at > now())`))
    const row = rows[0]
    // The same answer for another organization's artifact as for none at all,
    // so this cannot be used to ask whether an identifier exists elsewhere,
    // and the same again for one that has expired.
    if (!row) return c.json({ error: 'No artifact with that identifier.' }, 404)

    const allowed = await permits({
      orgId: session.orgId, userId: session.userId, role: session.role,
      permission: 'environments.view', repository: null, envId: row.env_id,
    })
    if (!allowed) {
      return c.json({ error: 'This needs the environments.view permission, which your role does not have.' }, 403)
    }
    if (!row.retained) {
      return c.json({ error: 'This artifact was removed by the organization\'s retention.' }, 410)
    }
    // Served only as a type its kind may be. A row a fixture wrote with some
    // other type, or with a kind this code does not know, is not served as
    // anything, because the type is the one thing the browser trusts.
    const contentType = row.content_type ?? ''
    if (!isArtifactKind(row.kind) || !KIND_POLICIES[row.kind].contentTypes.includes(contentType)) {
      return c.json({ error: 'This artifact\'s bytes are not available.' }, 410)
    }
    const size = Number(row.size_bytes ?? 0)
    const store = stores.reader(row.backend)
    if (!store || size <= 0) {
      return c.json({ error: 'This artifact\'s bytes are not available.' }, 410)
    }

    let range
    try {
      range = parseRange(c.req.header('range'), size)
    } catch {
      c.header('content-range', `bytes */${size}`)
      return c.body(null, 416)
    }

    const scope = <T>(fn: (db: Db) => Promise<T>) => pool.withTenant(tenant, fn)
    const opened = await store.open(scope, {
      id: row.id, orgId: row.org_id, locator: row.storage_key, sizeBytes: size, contentType,
    }, range)
    if (opened.kind === 'missing') {
      return c.json({ error: 'This artifact\'s bytes are not available.' }, 410)
    }
    if (opened.kind === 'redirect') {
      c.header('location', opened.url)
      return c.body(null, 302)
    }

    c.header('content-type', contentType)
    c.header('content-disposition', contentDisposition(row.kind, row.workflow, contentType))
    c.header('accept-ranges', 'bytes')
    const length = range ? range.end - range.start + 1 : size
    c.header('content-length', String(length))
    if (range) c.header('content-range', `bytes ${range.start}-${range.end}/${size}`)
    // A HEAD reaches this handler too, and Hono drops the body on the way out.
    // The stream is lazy, so nothing past the shape check is read for one.
    return c.body(opened.body, range ? 206 : 200)
  }

  app.get('/v1/artifacts/:id', (c) => download(c))
}
