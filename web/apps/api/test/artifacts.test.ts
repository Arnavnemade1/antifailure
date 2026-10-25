// Run artifacts: the upload an engine makes, the download a member makes, the
// switch an organization turns on, and the retention that removes them.
//
// Every refusal here is a specific way the evidence could end up somewhere it
// should not: in an organization that never agreed to hold it, under another
// organization's run, as a file of a type it is not, or kept past the day it
// was meant to go. The first half needs no database; the second runs the real
// server against the real schema, because the guarantees that matter most are
// row level security and the sweeper's role, and neither exists without one.

import { after, before, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import {
  ArtifactRefusal, KIND_POLICIES, bytesMatchType, contentDisposition, parseRange, readDeclaration,
} from '../src/artifacts/policy.ts'
import {
  ByteBudget, DEFAULT_IN_FLIGHT_BYTES, DEFAULT_ORG_QUOTA_BYTES, artifactQuotaBytesFrom, readExactly,
} from '../src/artifacts/routes.ts'
import { ArtifactStores } from '../src/artifacts/store.ts'
import { CHUNK_BYTES, PostgresArtifactStore } from '../src/artifacts/postgres-store.ts'
import { sweepExpiredArtifacts } from '../src/artifacts/sweep.ts'
import {
  available, callProcedure, dropOrg, errorCode, seedOrg, signInAs, startApi,
  type ApiHarness, type Org,
} from './harness.ts'

const hasDatabase = await available()

// ---------------------------------------------------------------------------
// Bytes that are what they say they are
// ---------------------------------------------------------------------------

/** A body that starts the way a WebM file does, filled deterministically. */
function webm(size: number, seed = 1): Buffer {
  const out = Buffer.alloc(size)
  for (let i = 0; i < size; i++) out[i] = (i * 31 + seed * 7) & 0xff
  out.set([0x1a, 0x45, 0xdf, 0xa3], 0)
  return out
}

function png(size: number): Buffer {
  const out = Buffer.alloc(size, 0x42)
  out.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], 0)
  return out
}

function zip(size: number): Buffer {
  const out = Buffer.alloc(size, 0x11)
  out.set([0x50, 0x4b, 0x03, 0x04], 0)
  return out
}

const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex')

function headers(map: Record<string, string>) {
  return (name: string) => map[name.toLowerCase()]
}

// ---------------------------------------------------------------------------
// The declaration, read before a byte of the body
// ---------------------------------------------------------------------------

describe('what an upload may declare', () => {
  const ok = {
    'x-artifact-kind': 'video',
    'x-artifact-workflow': encodeURIComponent('Checkout as a returning customer'),
    'content-type': 'video/webm',
    'content-length': '1024',
    'x-artifact-sha256': 'a'.repeat(64),
  }

  it('reads a well formed declaration, including a workflow in another script', () => {
    const d = readDeclaration(headers({ ...ok, 'x-artifact-workflow': encodeURIComponent('購入する'), 'x-artifact-step': '3' }))
    assert.deepEqual(d, {
      kind: 'video', workflow: '購入する', step: 3, contentType: 'video/webm',
      sizeBytes: 1024, sha256: 'a'.repeat(64),
    })
  })

  const refusals: Array<[string, Record<string, string>, number, string]> = [
    ['a kind the runner does not make', { 'x-artifact-kind': 'har' }, 400, 'kind'],
    ['no workflow', { 'x-artifact-workflow': '' }, 400, 'workflow'],
    ['a workflow that is not valid percent encoding', { 'x-artifact-workflow': '%E0%A4%A' }, 400, 'workflow'],
    ['a control character in the workflow', { 'x-artifact-workflow': encodeURIComponent('a\nb') }, 400, 'workflow'],
    ['a video that says it is HTML', { 'content-type': 'text/html' }, 415, 'content_type'],
    ['a screenshot type for a video', { 'content-type': 'image/png' }, 415, 'content_type'],
    ['no Content-Length', { 'content-length': '' }, 411, 'length'],
    ['an empty body', { 'content-length': '0' }, 400, 'length'],
    ['a video over its ceiling', { 'content-length': String(KIND_POLICIES.video.maxBytes + 1) }, 413, 'too_large'],
    ['a digest that is not one', { 'x-artifact-sha256': 'not-hex' }, 400, 'digest'],
    ['a step that is not a number', { 'x-artifact-step': '-1' }, 400, 'step'],
  ]
  for (const [name, change, status, code] of refusals) {
    it(`refuses ${name}`, () => {
      assert.throws(() => readDeclaration(headers({ ...ok, ...change })), (err: unknown) => {
        assert.ok(err instanceof ArtifactRefusal, String(err))
        assert.equal(err.status, status)
        assert.equal(err.code, code)
        return true
      })
    })
  }

  it('holds a screenshot to its own, smaller ceiling', () => {
    assert.throws(
      () => readDeclaration(headers({
        ...ok, 'x-artifact-kind': 'screenshot', 'content-type': 'image/png',
        'content-length': String(KIND_POLICIES.screenshot.maxBytes + 1),
      })),
      (err: unknown) => err instanceof ArtifactRefusal && err.status === 413,
    )
  })
})

describe('whether bytes are the type they claim', () => {
  it('accepts each type by its own signature', () => {
    assert.ok(bytesMatchType(webm(64), 'video/webm'))
    assert.ok(bytesMatchType(png(64), 'image/png'))
    assert.ok(bytesMatchType(zip(64), 'application/zip'))
    assert.ok(bytesMatchType(Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 0]), 'image/jpeg'))
    const mp4 = Buffer.alloc(16)
    mp4.set([0, 0, 0, 0x18, 0x66, 0x74, 0x79, 0x70], 0)
    assert.ok(bytesMatchType(mp4, 'video/mp4'))
  })

  it('refuses HTML however it is labelled, which is the case this exists for', () => {
    const page = Buffer.from('<html><script>alert(document.cookie)</script></html>')
    for (const type of ['image/png', 'image/jpeg', 'video/webm', 'video/mp4', 'application/zip']) {
      assert.equal(bytesMatchType(page, type), false, `HTML passed as ${type}`)
    }
  })

  it('refuses a real file under the wrong one of its kind\'s types', () => {
    assert.equal(bytesMatchType(png(64), 'image/jpeg'), false)
    assert.equal(bytesMatchType(webm(64), 'video/mp4'), false)
  })
})

describe('how a download is named', () => {
  it('names it from the workflow and the kind, in both the plain and the encoded parameter', () => {
    assert.equal(
      contentDisposition('video', 'Sign in', 'video/webm'),
      `inline; filename="Sign-in-video.webm"; filename*=UTF-8''Sign%20in-video.webm`,
    )
  })

  it('saves a trace rather than showing it', () => {
    assert.match(contentDisposition('trace', 'checkout', 'application/zip'), /^attachment; filename="checkout-trace\.zip"/)
  })

  it('cannot be ended early by a quote in the workflow name', () => {
    const header = contentDisposition('screenshot', 'say "hi"; filename=evil.html', 'image/png')
    assert.equal((header.match(/"/g) ?? []).length, 2, header)
    assert.ok(!header.includes('evil.html"'), header)
    assert.ok(header.includes("filename*=UTF-8''say%20%22hi%22%3B%20filename%3Devil.html-screenshot.png"), header)
  })
})

describe('the ranges a video asks for', () => {
  it('reads the three shapes a video element sends', () => {
    assert.deepEqual(parseRange('bytes=0-99', 1000), { start: 0, end: 99 })
    assert.deepEqual(parseRange('bytes=900-', 1000), { start: 900, end: 999 })
    assert.deepEqual(parseRange('bytes=-100', 1000), { start: 900, end: 999 })
    assert.deepEqual(parseRange('bytes=990-5000', 1000), { start: 990, end: 999 })
    assert.equal(parseRange(undefined, 1000), null)
  })

  it('refuses one it cannot satisfy', () => {
    for (const bad of ['bytes=1000-', 'bytes=5-2', 'bytes=0-1,4-5', 'items=0-1', 'bytes=-0']) {
      assert.throws(() => parseRange(bad, 1000), RangeError, bad)
    }
  })
})

describe('the memory upload bodies may hold', () => {
  it('never lends more than it has, and takes back what it lent', () => {
    const budget = new ByteBudget(100)
    assert.ok(budget.reserve(60))
    assert.equal(budget.reserve(41), false)
    assert.ok(budget.reserve(40))
    budget.release(60)
    assert.equal(budget.inUse, 40)
    assert.equal(budget.reserve(101), false, 'one body larger than the whole budget')
  })
})

describe('reading exactly the declared body', () => {
  const request = (body: Buffer) =>
    new Request('http://x.test/', { method: 'POST', body, headers: { 'content-length': String(body.length) } })

  it('reads a body of the declared length', async () => {
    const body = webm(5000)
    assert.deepEqual(await readExactly(request(body), body.length, 5000), body)
  })

  it('refuses one longer than it declared, and one shorter', async () => {
    await assert.rejects(readExactly(request(webm(5000)), 4000, 5000),
      (err: unknown) => err instanceof ArtifactRefusal && err.code === 'length')
    await assert.rejects(readExactly(request(webm(3000)), 4000, 5000),
      (err: unknown) => err instanceof ArtifactRefusal && /3000 bytes/.test(err.message))
  })

  it('refuses one that does not arrive in time, rather than waiting on it', async () => {
    const stalled = new Request('http://x.test/', {
      method: 'POST',
      body: new ReadableStream({ start(c) { c.enqueue(new Uint8Array([1, 2, 3])) } }),
      duplex: 'half',
    } as RequestInit)
    await assert.rejects(readExactly(stalled, 10, 50),
      (err: unknown) => err instanceof ArtifactRefusal && err.code === 'too_slow')
  })
})

// ---------------------------------------------------------------------------
// Against the real server and the real schema
// ---------------------------------------------------------------------------

describe('artifacts over HTTP', { skip: hasDatabase ? false : 'no Postgres at AF_TEST_DATABASE_URL' }, () => {
  let h: ApiHarness
  let org: Org
  let other: Org
  let token: string
  let otherToken: string

  async function engineToken(o: Org, name: string): Promise<string> {
    const t = `aft_${randomUUID().replace(/-/g, '')}`
    await h.admin`
      INSERT INTO engine_tokens (org_id, name, token_hash, prefix)
      VALUES (${o.orgId}, ${name}, ${createHash('sha256').update(t).digest()}, 'aft_test')`
    return t
  }

  async function startRun(o: Org, bearer: string, runId: string): Promise<void> {
    const res = await h.fetch('/v1/events', {
      method: 'POST',
      headers: { authorization: `Bearer ${bearer}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        events: [{
          id: randomUUID(), type: 'run.started', envId: o.envId, sequence: 1,
          occurredAt: h.clock.now().toISOString(),
          payload: { run_id: runId, kind: 'workflows', started_at: h.clock.now().toISOString() },
        }],
      }),
    })
    assert.equal(res.status, 202, await res.text())
  }

  interface UploadOptions {
    kind?: string
    workflow?: string
    contentType?: string
    step?: number
    digest?: string
    envId?: string
  }

  async function upload(bearer: string, o: Org, runId: string, body: Buffer, opts: UploadOptions = {}) {
    const res = await h.fetch(
      `/v1/environments/${encodeURIComponent(opts.envId ?? o.envId)}/runs/${encodeURIComponent(runId)}/artifacts`,
      {
        method: 'POST',
        headers: {
          authorization: `Bearer ${bearer}`,
          // Set by hand because the harness hands a Request straight to the
          // app, and a Request built in process carries no Content-Length the
          // way one sent over a socket does. The route requires it.
          'content-length': String(body.length),
          'content-type': opts.contentType ?? 'video/webm',
          'x-artifact-kind': opts.kind ?? 'video',
          'x-artifact-workflow': encodeURIComponent(opts.workflow ?? 'Sign in'),
          'x-artifact-sha256': opts.digest ?? sha(body),
          ...(opts.step === undefined ? {} : { 'x-artifact-step': String(opts.step) }),
        },
        body,
      },
    )
    const text = await res.text()
    let json: any = null
    try { json = JSON.parse(text) } catch { json = text }
    return { status: res.status, body: json, retryAfter: res.headers.get('retry-after') }
  }

  async function setStorage(o: Org, enabled: boolean, retentionDays = 30) {
    const owner = await signInAs(h, o, 'owner')
    const res = await callProcedure(h, owner, 'org.setArtifactStorage', 'mutation', { enabled, retentionDays })
    assert.equal(res.status, 200, JSON.stringify(res.body))
  }

  const count = async (sqlText: string, ...values: unknown[]) => {
    const rows = await h.admin.unsafe(sqlText, values as never[])
    return Number((rows[0] as unknown as { n: string }).n)
  }

  before(async () => {
    h = await startApi()
    org = await seedOrg(h.admin, 'evidence')
    other = await seedOrg(h.admin, 'elsewhere')
    token = await engineToken(org, 'ci')
    otherToken = await engineToken(other, 'ci')
  })

  after(async () => {
    await dropOrg(h.admin, org.orgId)
    await dropOrg(h.admin, other.orgId)
    await h.close()
  })

  it('refuses every upload until somebody turns storage on, and says how', async () => {
    const runId = `run_${randomUUID()}`
    await startRun(org, token, runId)
    const refused = await upload(token, org, runId, webm(2048))
    assert.equal(refused.status, 403)
    assert.equal(refused.body.code, 'uploads_disabled')
    assert.match(refused.body.error, /Settings, Artifacts/)
    assert.equal(await count(`SELECT count(*)::text AS n FROM artifacts WHERE org_id = $1`, org.orgId), 0)
  })

  it('lets an owner turn it on and a member not, and audits the switch with what it was', async () => {
    const member = await signInAs(h, org, 'member')
    const refused = await callProcedure(h, member, 'org.setArtifactStorage', 'mutation', {
      enabled: true, retentionDays: 30,
    })
    assert.equal(errorCode(refused.body), 'FORBIDDEN')

    const viewer = await signInAs(h, org, 'viewer')
    const read = await callProcedure(h, viewer, 'org.artifactStorage', 'query', {})
    assert.equal(read.status, 200)
    assert.equal((read.body as any).result.data.enabled, false, 'a viewer can see that storage is off')

    await setStorage(org, true, 14)
    const audit = await h.admin<{ action: string; detail: any }[]>`
      SELECT action, detail FROM audit_entries
      WHERE org_id = ${org.orgId} AND action LIKE 'organization.artifacts%' ORDER BY seq`
    assert.equal(audit.at(-1)?.action, 'organization.artifacts_enabled')
    assert.deepEqual(audit.at(-1)?.detail.enabled, { from: false, to: true })
    assert.deepEqual(audit.at(-1)?.detail.retentionDays, { from: 30, to: 14 })

    // A retention change on storage that was already on is not the switch.
    await setStorage(org, true, 30)
    const latest = await h.admin<{ action: string }[]>`
      SELECT action FROM audit_entries
      WHERE org_id = ${org.orgId} AND action LIKE 'organization.artifacts%' ORDER BY seq DESC LIMIT 1`
    assert.equal(latest[0]?.action, 'organization.artifacts_retention_changed')
  })

  it('tells an upload that overtook its run to wait for it', async () => {
    await setStorage(org, true)
    const early = await upload(token, org, `run_${randomUUID()}`, webm(1024))
    assert.equal(early.status, 409)
    assert.equal(early.body.code, 'run_not_recorded')
    assert.equal(early.retryAfter, '5')
  })

  it('stores a video, answers a retry with the same row, and refuses a different file in its place', async () => {
    await setStorage(org, true, 7)
    const runId = `run_${randomUUID()}`
    await startRun(org, token, runId)
    const body = webm(4096, 2)
    const first = await upload(token, org, runId, body, { workflow: 'Checkout' })
    assert.equal(first.status, 201, JSON.stringify(first.body))
    assert.equal(first.body.created, true)
    assert.equal(first.body.size_bytes, 4096)
    assert.equal(first.body.sha256, sha(body))
    // Measured against the real clock, because the expiry is the database's
    // now() plus the retention, which is the clock the sweeper reads.
    const expires = new Date(first.body.expires_at).getTime() - Date.now()
    assert.equal(Math.round(expires / 86_400_000), 7, 'the expiry is the organization\'s retention')

    const retry = await upload(token, org, runId, body, { workflow: 'Checkout' })
    assert.equal(retry.status, 200)
    assert.equal(retry.body.created, false)
    assert.equal(retry.body.id, first.body.id)

    const different = await upload(token, org, runId, webm(4096, 3), { workflow: 'Checkout' })
    assert.equal(different.status, 409)
    assert.equal(different.body.code, 'artifact_exists')

    // The same workflow's screenshot is its own slot.
    const shot = await upload(token, org, runId, png(1000), {
      workflow: 'Checkout', kind: 'screenshot', contentType: 'image/png',
    })
    assert.equal(shot.status, 201)
    assert.equal(await count(`SELECT count(*)::text AS n FROM artifacts WHERE id = $1 AND retained`, first.body.id), 1)
    assert.equal(await count(`SELECT count(*)::text AS n FROM artifact_chunks WHERE artifact_id = $1`, first.body.id), 1)
  })

  it('refuses a body that is not the file it declares, and keeps nothing of it', async () => {
    const runId = `run_${randomUUID()}`
    await startRun(org, token, runId)
    const body = webm(2048)
    const wrongDigest = await upload(token, org, runId, body, {
      digest: sha(webm(2048, 9)), workflow: 'Mismatched',
    })
    assert.equal(wrongDigest.status, 422)
    assert.equal(wrongDigest.body.code, 'digest_mismatch')

    const page = Buffer.from('<html><script>alert(document.cookie)</script></html>')
    const disguised = await upload(token, org, runId, page, {
      kind: 'screenshot', contentType: 'image/png', workflow: 'Disguised',
    })
    assert.equal(disguised.status, 415)
    assert.equal(disguised.body.code, 'content_mismatch')

    assert.equal(await count(
      `SELECT count(*)::text AS n FROM artifacts WHERE org_id = $1 AND workflow IN ('Mismatched', 'Disguised')`,
      org.orgId), 0, 'a refused upload left a row')
  })

  it('cannot file one organization\'s evidence under another\'s run', async () => {
    const runId = `run_${randomUUID()}`
    await startRun(org, token, runId)
    await setStorage(other, true)
    // The other organization's token, naming this organization's environment
    // and run. The run row is derived from the token's organization, so there
    // is no such run for it, and nothing lands here.
    const crossed = await upload(otherToken, org, runId, webm(1024), { workflow: 'Crossed' })
    assert.equal(crossed.status, 409)
    assert.equal(crossed.body.code, 'run_not_recorded')
    assert.equal(await count(
      `SELECT count(*)::text AS n FROM artifacts WHERE workflow = 'Crossed'`), 0)
  })

  it('serves the bytes back to a member, whole and in ranges across a chunk boundary', async () => {
    await setStorage(org, true)
    const runId = `run_${randomUUID()}`
    await startRun(org, token, runId)
    const body = webm(Math.floor(CHUNK_BYTES * 2.5), 5)
    const stored = await upload(token, org, runId, body, { workflow: 'Long recording' })
    assert.equal(stored.status, 201, JSON.stringify(stored.body))
    assert.equal(await count(
      `SELECT count(*)::text AS n FROM artifact_chunks WHERE artifact_id = $1`, stored.body.id), 3)

    const viewer = await signInAs(h, org, 'viewer')
    const whole = await h.fetch(`/v1/artifacts/${stored.body.id}`, { headers: { cookie: viewer.cookie } })
    assert.equal(whole.status, 200)
    assert.equal(whole.headers.get('content-type'), 'video/webm')
    assert.equal(whole.headers.get('content-length'), String(body.length))
    assert.equal(whole.headers.get('accept-ranges'), 'bytes')
    assert.equal(whole.headers.get('x-content-type-options'), 'nosniff')
    assert.match(whole.headers.get('content-security-policy') ?? '', /sandbox/)
    assert.match(whole.headers.get('content-disposition') ?? '', /^inline; filename="Long-recording-video\.webm"/)
    assert.ok(Buffer.from(await whole.arrayBuffer()).equals(body), 'the bytes came back different')

    // A range straddling the first chunk boundary.
    const start = CHUNK_BYTES - 10
    const end = CHUNK_BYTES + 9
    const part = await h.fetch(`/v1/artifacts/${stored.body.id}`, {
      headers: { cookie: viewer.cookie, range: `bytes=${start}-${end}` },
    })
    assert.equal(part.status, 206)
    assert.equal(part.headers.get('content-range'), `bytes ${start}-${end}/${body.length}`)
    assert.ok(Buffer.from(await part.arrayBuffer()).equals(body.subarray(start, end + 1)))

    // The last bytes, the way a player asks for the end of a file.
    const tail = await h.fetch(`/v1/artifacts/${stored.body.id}`, {
      headers: { cookie: viewer.cookie, range: 'bytes=-100' },
    })
    assert.equal(tail.status, 206)
    assert.ok(Buffer.from(await tail.arrayBuffer()).equals(body.subarray(body.length - 100)))

    const beyond = await h.fetch(`/v1/artifacts/${stored.body.id}`, {
      headers: { cookie: viewer.cookie, range: `bytes=${body.length}-` },
    })
    assert.equal(beyond.status, 416)
    assert.equal(beyond.headers.get('content-range'), `bytes */${body.length}`)

    const head = await h.fetch(`/v1/artifacts/${stored.body.id}`, {
      method: 'HEAD', headers: { cookie: viewer.cookie },
    })
    assert.equal(head.status, 200)
    assert.equal(head.headers.get('content-length'), String(body.length))
  })

  it('gives another organization\'s member, a signed out browser and a made up identifier nothing', async () => {
    const runId = `run_${randomUUID()}`
    await startRun(org, token, runId)
    const stored = await upload(token, org, runId, png(500), {
      kind: 'screenshot', contentType: 'image/png', workflow: 'Private',
    })
    assert.equal(stored.status, 201)

    const stranger = await signInAs(h, other, 'owner')
    const foreign = await h.fetch(`/v1/artifacts/${stored.body.id}`, { headers: { cookie: stranger.cookie } })
    assert.equal(foreign.status, 404, 'another organization learned the artifact exists')
    const missing = await h.fetch(`/v1/artifacts/${randomUUID()}`, { headers: { cookie: stranger.cookie } })
    assert.equal(missing.status, 404)
    assert.deepEqual(await foreign.json(), await missing.json(), 'the two refusals differ')

    const anonymous = await h.fetch(`/v1/artifacts/${stored.body.id}`)
    assert.equal(anonymous.status, 401)

    const garbage = await h.fetch('/v1/artifacts/not-a-uuid', { headers: { cookie: stranger.cookie } })
    assert.equal(garbage.status, 400)
  })

  it('lists what a run kept, with the workflow each artifact belongs to', async () => {
    const runId = `run_${randomUUID()}`
    await startRun(org, token, runId)
    await upload(token, org, runId, webm(1500), { workflow: 'Browse' })
    await upload(token, org, runId, zip(800), { workflow: 'Browse', kind: 'trace', contentType: 'application/zip' })

    const viewer = await signInAs(h, org, 'viewer')
    const runRow = await h.admin<{ id: string }[]>`
      SELECT r.id FROM runs r JOIN artifacts a ON a.run_id = r.id
      WHERE a.org_id = ${org.orgId} AND a.workflow = 'Browse' LIMIT 1`
    const listed = await callProcedure(h, viewer, 'runs.artifacts', 'query', { runId: runRow[0]!.id })
    assert.equal(listed.status, 200, JSON.stringify(listed.body))
    const rows = (listed.body as any).result.data as Array<{ kind: string; workflow: string; size_bytes: number }>
    assert.deepEqual(rows.map((r) => [r.workflow, r.kind, r.size_bytes]), [
      ['Browse', 'trace', 800],
      ['Browse', 'video', 1500],
    ])
  })

  it('refuses an organization that is suspended, as every engine write does', async () => {
    const runId = `run_${randomUUID()}`
    await startRun(org, token, runId)
    await h.admin`UPDATE organizations SET suspended_at = now(), suspended_reason = 'incident' WHERE id = ${org.orgId}`
    try {
      const refused = await upload(token, org, runId, webm(1024), { workflow: 'During the incident' })
      assert.equal(refused.status, 403)
      assert.equal(refused.body.code, 'suspended')
    } finally {
      await h.admin`UPDATE organizations SET suspended_at = NULL, suspended_reason = NULL WHERE id = ${org.orgId}`
    }
  })

  it('confirms an artifact.stored event for a real artifact, and notes one that never landed', async () => {
    const runId = `run_${randomUUID()}`
    await startRun(org, token, runId)
    const stored = await upload(token, org, runId, webm(900), { workflow: 'Reported' })
    assert.equal(stored.status, 201)

    const send = async (artifactId: string) => {
      const res = await h.fetch('/v1/events', {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          events: [{
            id: randomUUID(), type: 'artifact.stored', envId: org.envId, sequence: 2,
            occurredAt: h.clock.now().toISOString(),
            payload: { run_id: runId, artifact_id: artifactId, kind: 'video', workflow: 'Reported' },
          }],
        }),
      })
      return (await res.json()) as { outcomes: Array<{ status: string; note?: string }> }
    }
    const real = await send(stored.body.id)
    assert.equal(real.outcomes[0]?.status, 'accepted')
    assert.equal(real.outcomes[0]?.note, undefined)

    const imagined = await send(randomUUID())
    assert.equal(imagined.outcomes[0]?.status, 'accepted')
    assert.match(imagined.outcomes[0]?.note ?? '', /did not land here/)
  })

  it('reports what the organization holds against its quota', async () => {
    const owner = await signInAs(h, org, 'owner')
    const read = await callProcedure(h, owner, 'org.artifactStorage', 'query', {})
    const data = (read.body as any).result.data
    const held = await count(
      `SELECT coalesce(sum(size_bytes), 0)::text AS n FROM artifacts WHERE org_id = $1 AND retained`, org.orgId)
    assert.equal(data.usedBytes, held)
    assert.ok(data.usedBytes > 0)
    assert.equal(data.enabled, true)
  })

  it('removes expired bytes, keeps the row, and stops serving it', async () => {
    await setStorage(org, true)
    const runId = `run_${randomUUID()}`
    await startRun(org, token, runId)
    const stored = await upload(token, org, runId, webm(3000), { workflow: 'Old news' })
    assert.equal(stored.status, 201)
    // Expired by the database's own clock, which is the only clock the
    // sweeper's policy reads.
    await h.admin`UPDATE artifacts SET expires_at = now() - interval '1 day' WHERE id = ${stored.body.id}`
    await h.admin`UPDATE artifact_chunks SET expires_at = now() - interval '1 day' WHERE artifact_id = ${stored.body.id}`

    const swept = await sweepExpiredArtifacts(h.pool, new ArtifactStores(new PostgresArtifactStore()))
    assert.ok(swept.removed >= 1, JSON.stringify(swept))
    assert.equal(swept.unreachable, 0)
    assert.equal(await count(`SELECT count(*)::text AS n FROM artifact_chunks WHERE artifact_id = $1`, stored.body.id), 0)
    assert.equal(await count(`SELECT count(*)::text AS n FROM artifacts WHERE id = $1 AND NOT retained`, stored.body.id), 1)

    const viewer = await signInAs(h, org, 'viewer')
    const gone = await h.fetch(`/v1/artifacts/${stored.body.id}`, { headers: { cookie: viewer.cookie } })
    assert.equal(gone.status, 404)
  })

  it('stops serving a file the moment it expires, before the sweep reaches it', async () => {
    await setStorage(org, true)
    const runId = `run_${randomUUID()}`
    await startRun(org, token, runId)
    const body = webm(2500, 9)
    const stored = await upload(token, org, runId, body, { workflow: 'Past due' })
    assert.equal(stored.status, 201, JSON.stringify(stored.body))
    const viewer = await signInAs(h, org, 'viewer')
    const open = () => h.fetch(`/v1/artifacts/${stored.body.id}`, { headers: { cookie: viewer.cookie } })

    // Served while it is in date, which is what makes the refusal below
    // about the expiry and not about the file.
    const before = await open()
    assert.equal(before.status, 200)
    assert.ok(Buffer.from(await before.arrayBuffer()).equals(body))

    // Past its expiry by the database's clock, with every byte still there
    // and the row still saying retained: exactly the state between the expiry
    // and the next sweep.
    await h.admin`UPDATE artifacts SET expires_at = now() - interval '1 second' WHERE id = ${stored.body.id}`
    assert.equal(await count(`SELECT count(*)::text AS n FROM artifact_chunks WHERE artifact_id = $1`, stored.body.id), 1)
    assert.equal(await count(`SELECT count(*)::text AS n FROM artifacts WHERE id = $1 AND retained`, stored.body.id), 1)

    const after = await open()
    const missing = await h.fetch(`/v1/artifacts/${randomUUID()}`, { headers: { cookie: viewer.cookie } })
    assert.equal(after.status, 404)
    assert.equal(after.status, missing.status)
    assert.deepEqual(await after.json(), await missing.json(), 'an expired file answers differently from a missing one')

    // And the run page no longer lists it as kept, so it offers no link to it.
    const listed = await callProcedure(h, viewer, 'runs.artifacts', 'query', {
      runId: (await h.admin<{ id: string }[]>`SELECT run_id AS id FROM artifacts WHERE id = ${stored.body.id}`)[0]!.id,
    })
    const row = ((listed.body as any).result.data as Array<{ id: string; retained: boolean }>)
      .find((a) => a.id === stored.body.id)
    assert.equal(row?.retained, false)
  })

  it('does not reach an artifact that has not expired', async () => {
    await setStorage(org, true)
    const runId = `run_${randomUUID()}`
    await startRun(org, token, runId)
    const stored = await upload(token, org, runId, webm(1200), { workflow: 'Current' })
    assert.equal(stored.status, 201, JSON.stringify(stored.body))
    await sweepExpiredArtifacts(h.pool, new ArtifactStores(new PostgresArtifactStore()))
    assert.equal(await count(`SELECT count(*)::text AS n FROM artifact_chunks WHERE artifact_id = $1`, stored.body.id), 1)
    assert.equal(await count(`SELECT count(*)::text AS n FROM artifacts WHERE id = $1 AND retained`, stored.body.id), 1)
  })

  it('leaves an artifact in a backend this process cannot reach exactly as it is', async () => {
    await setStorage(org, true)
    const runId = `run_${randomUUID()}`
    await startRun(org, token, runId)
    const stored = await upload(token, org, runId, webm(1300), { workflow: 'Elsewhere' })
    assert.equal(stored.status, 201, JSON.stringify(stored.body))
    await h.admin`UPDATE artifacts SET backend = 'azure_blob', expires_at = now() - interval '1 day' WHERE id = ${stored.body.id}`
    const swept = await sweepExpiredArtifacts(h.pool, new ArtifactStores(new PostgresArtifactStore()))
    assert.ok(swept.unreachable >= 1)
    assert.equal(await count(`SELECT count(*)::text AS n FROM artifacts WHERE id = $1 AND retained`, stored.body.id), 1)
  })
})

describe('the organization quota', { skip: hasDatabase ? false : 'no Postgres at AF_TEST_DATABASE_URL' }, () => {
  let h: ApiHarness
  let org: Org
  let t: string

  before(async () => {
    h = await startApi({ artifactLimits: { orgQuotaBytes: 5000 } })
    org = await seedOrg(h.admin, 'quota')
    t = `aft_${randomUUID().replace(/-/g, '')}`
    await h.admin`
      INSERT INTO engine_tokens (org_id, name, token_hash, prefix)
      VALUES (${org.orgId}, 'ci', ${createHash('sha256').update(t).digest()}, 'aft_test')`
    await h.admin`UPDATE organizations SET artifact_uploads_enabled = true WHERE id = ${org.orgId}`
  })

  after(async () => {
    await dropOrg(h.admin, org.orgId)
    await h.close()
  })

  /** Each test starts from an organization that keeps nothing. */
  async function empty(): Promise<void> {
    await h.admin`DELETE FROM artifacts WHERE org_id = ${org.orgId}`
  }

  async function newRun(): Promise<string> {
    const runId = `run_${randomUUID()}`
    const started = await h.fetch('/v1/events', {
      method: 'POST',
      headers: { authorization: `Bearer ${t}`, 'content-type': 'application/json' },
      body: JSON.stringify({ events: [{
        id: randomUUID(), type: 'run.started', envId: org.envId, sequence: 1,
        occurredAt: h.clock.now().toISOString(), payload: { run_id: runId },
      }] }),
    })
    assert.equal(started.status, 202)
    return runId
  }

  const send = (runId: string, body: Buffer, workflow: string) => h.fetch(
    `/v1/environments/${org.envId}/runs/${runId}/artifacts`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${t}`, 'content-length': String(body.length),
        'content-type': 'video/webm', 'x-artifact-kind': 'video',
        'x-artifact-workflow': workflow, 'x-artifact-sha256': sha(body),
      },
      body,
    })

  const kept = async () => {
    const [row] = await h.admin<{ n: string }[]>`
      SELECT coalesce(sum(size_bytes), 0)::text AS n FROM artifacts WHERE org_id = ${org.orgId} AND retained`
    return Number(row!.n)
  }

  it('refuses the upload that would take an organization past what it may keep', async () => {
    await empty()
    const runId = await newRun()
    assert.equal((await send(runId, webm(3000), 'first')).status, 201)
    const over = await send(runId, webm(3000), 'second')
    assert.equal(over.status, 507)
    const refusal = (await over.json()) as { code: string; error: string }
    assert.equal(refusal.code, 'quota')
    // The engine repeats this sentence to a person, so it is in their units,
    // and it does not send them to the retention setting, which applies only
    // to files stored after it changes and so frees nothing today.
    assert.match(refusal.error, /at most 0\.0 MiB of artifacts and holds 0\.0 MiB/)
    assert.doesNotMatch(refusal.error, /retention/)
  })

  // The orderings two uploads for two DIFFERENT runs of one organization can
  // arrive in, each 3000 bytes against a quota of 5000, so that either fits
  // alone and the two together do not. The lock that serialized them was per
  // run, so different runs is the case it did not cover.

  it('A then B, for different runs: the second is refused', async () => {
    await empty()
    const [a, b] = [await newRun(), await newRun()]
    assert.equal((await send(a, webm(3000, 2), 'A')).status, 201)
    assert.equal((await send(b, webm(3000, 3), 'B')).status, 507)
    assert.equal(await kept(), 3000)
  })

  it('B then A, for different runs: the second is refused', async () => {
    await empty()
    const [a, b] = [await newRun(), await newRun()]
    assert.equal((await send(b, webm(3000, 4), 'B')).status, 201)
    assert.equal((await send(a, webm(3000, 5), 'A')).status, 507)
    assert.equal(await kept(), 3000)
  })

  it('A and B at once, for different runs: one is kept and the quota holds', async () => {
    await empty()
    const [a, b] = [await newRun(), await newRun()]

    // The interleaving that overshot, forced rather than hoped for. Holding
    // an EXCLUSIVE lock on artifact_chunks stops each upload at its first
    // chunk write, which is AFTER its quota check and its artifacts row. With
    // nothing serializing the two, both reach that point having read the same
    // empty total, both are waiting when the lock is released, and both
    // commit. With them serialized per organization, the second waits before
    // its quota check, and reads the first one's row once it is committed.
    // Released only once two uploads are waiting on a lock, so the test is
    // about the two arriving together and not about which one the event loop
    // happened to run first.
    // The uploads' promise is handed out wrapped, because a transaction
    // callback that returns a promise is awaited before the COMMIT, and the
    // COMMIT is what releases the uploads.
    const { inFlight } = await h.admin.begin(async (tx) => {
      await tx`LOCK TABLE artifact_chunks IN EXCLUSIVE MODE`
      const inFlight = Promise.all([send(a, webm(3000, 6), 'A'), send(b, webm(3000, 7), 'B')])
      const deadline = Date.now() + 15_000
      for (;;) {
        const [w] = await h.admin<{ n: string }[]>`
          SELECT count(*)::text AS n FROM pg_stat_activity
          WHERE datname = current_database() AND wait_event_type = 'Lock'`
        if (Number(w!.n) >= 2) break
        assert.ok(Date.now() < deadline, 'the two uploads never both reached a lock')
        await new Promise((r) => setTimeout(r, 20))
      }
      return { inFlight }
    })
    const results = await inFlight

    const statuses = results.map((r) => r.status).sort()
    assert.deepEqual(statuses, [201, 507], `both uploads answered ${statuses.join(' and ')}`)
    assert.ok(await kept() <= 5000, `the organization keeps ${await kept()} bytes against a quota of 5000`)
  })

  it('A with no B: one upload that fits is kept', async () => {
    await empty()
    assert.equal((await send(await newRun(), webm(4000, 8), 'alone')).status, 201)
    assert.equal(await kept(), 4000)
  })

  it('reports the quota it enforces, not the default', async () => {
    const owner = await signInAs(h, org, 'owner')
    const read = await callProcedure(h, owner, 'org.artifactStorage', 'query', {})
    assert.equal((read.body as any).result.data.quotaBytes, 5000)
  })
})

describe('the quota an installation sets', () => {
  it('is 256 MiB unless AF_ARTIFACT_ORG_QUOTA_MIB says otherwise', () => {
    assert.equal(DEFAULT_ORG_QUOTA_BYTES, 256 * 1024 * 1024)
    assert.equal(artifactQuotaBytesFrom(undefined), DEFAULT_ORG_QUOTA_BYTES)
    assert.equal(artifactQuotaBytesFrom(''), DEFAULT_ORG_QUOTA_BYTES)
    assert.equal(artifactQuotaBytesFrom(' 1024 '), 1024 * 1024 * 1024)
    assert.equal(artifactQuotaBytesFrom('1'), 1024 * 1024)
  })

  for (const bad of ['0', '-5', '1.5', '2GiB', 'lots', '1048577', '99999999']) {
    it(`stops the process on ${JSON.stringify(bad)} rather than guessing`, () => {
      assert.throws(() => artifactQuotaBytesFrom(bad), /AF_ARTIFACT_ORG_QUOTA_MIB must be a whole number/)
    })
  }

  it('holds no more upload bodies in memory than two of the largest kind', () => {
    assert.equal(DEFAULT_IN_FLIGHT_BYTES, 2 * KIND_POLICIES.video.maxBytes)
  })
})
