// The first ArtifactStore: the control plane's own database.
//
// An object is a run of rows in artifact_chunks, a megabyte each, in order. A
// megabyte because it is large enough that a sixty four megabyte video is
// sixty four rows rather than thousands, and small enough that reading one
// never holds more than that in this process or in a single statement.
//
// Reads are lazy. `open` checks that the chunks are all there and the sizes
// add up, then returns a stream that fetches one chunk per pull, each in its
// own short tenant transaction. A browser that pauses a video stops the reads,
// and one that seeks asks for a range, which is served from the chunks that
// cover it and no others, cut with substring so the bytes on either side of
// the range are never sent.

import { sql, type Db } from '@antifailure/db'
import type { ByteRange } from './policy.ts'
import type {
  ArtifactStore, OpenedArtifact, PutTarget, StoredArtifact, StoredObject, TenantScope,
} from './store.ts'

/** The size of a chunk, which the column's CHECK bounds from above. */
export const CHUNK_BYTES = 1024 * 1024

const BACKEND = 'postgres'
const PREFIX = 'pg:'

/** The locator for an artifact this store holds. */
export function postgresLocator(artifactId: string): string {
  return PREFIX + artifactId
}

/**
 * Whether a locator names the artifact it is recorded against.
 *
 * Checked on every read and every delete. A locator is a column a row carries,
 * and a row that pointed at another artifact's chunks would serve somebody
 * else's recording under a row this tenant can see. The chunks are tenant
 * scoped as well, so this is the second of two locks rather than the only one.
 */
function locatesItself(artifact: Pick<StoredArtifact, 'id' | 'locator'>): boolean {
  return artifact.locator === postgresLocator(artifact.id)
}

export class PostgresArtifactStore implements ArtifactStore {
  readonly backend = BACKEND

  async put(db: Db, target: PutTarget, bytes: Uint8Array): Promise<StoredObject> {
    if (bytes.byteLength === 0) {
      throw new Error('postgres artifact store: an object must hold at least one byte')
    }
    const expires = target.expiresAt.toISOString()
    for (let seq = 0, offset = 0; offset < bytes.byteLength; seq++, offset += CHUNK_BYTES) {
      const piece = Buffer.from(bytes.buffer, bytes.byteOffset + offset,
        Math.min(CHUNK_BYTES, bytes.byteLength - offset))
      await db.execute(sql`
        INSERT INTO artifact_chunks (org_id, artifact_id, seq, bytes, expires_at)
        VALUES (${target.orgId}::uuid, ${target.artifactId}::uuid, ${seq}, ${piece},
                ${expires}::timestamptz)`)
    }
    return { locator: postgresLocator(target.artifactId), sizeBytes: bytes.byteLength }
  }

  async open(scope: TenantScope, artifact: StoredArtifact, range: ByteRange | null): Promise<OpenedArtifact> {
    if (!locatesItself(artifact)) return { kind: 'missing' }

    // Every chunk present and the sizes adding up to what the row recorded,
    // checked before a byte is sent. A stream that discovers a gap halfway
    // through has already promised the browser a length it cannot deliver.
    const shape = await scope(async (db) => {
      const rows = await db.execute<{ chunks: string; bytes: string; last: number | null }>(sql`
        SELECT count(*)::text AS chunks,
               coalesce(sum(octet_length(bytes)), 0)::text AS bytes,
               max(seq) AS last
        FROM artifact_chunks WHERE artifact_id = ${artifact.id}::uuid`)
      return rows[0]
    })
    const chunks = Number(shape?.chunks ?? 0)
    if (chunks === 0 || Number(shape?.bytes) !== artifact.sizeBytes || shape?.last !== chunks - 1) {
      return { kind: 'missing' }
    }

    const start = range?.start ?? 0
    const end = range?.end ?? artifact.sizeBytes - 1
    let seq = Math.floor(start / CHUNK_BYTES)
    const lastSeq = Math.floor(end / CHUNK_BYTES)

    const body = new ReadableStream<Uint8Array>({
      pull: async (controller) => {
        if (seq > lastSeq) {
          controller.close()
          return
        }
        const chunkStart = seq * CHUNK_BYTES
        // One-based offsets, which is what substring counts in.
        const from = Math.max(start, chunkStart) - chunkStart + 1
        const length = Math.min(end, chunkStart + CHUNK_BYTES - 1) - Math.max(start, chunkStart) + 1
        const current = seq
        const piece = await scope(async (db) => {
          const rows = await db.execute<{ part: Buffer }>(sql`
            SELECT substring(bytes from ${from} for ${length}) AS part
            FROM artifact_chunks
            WHERE artifact_id = ${artifact.id}::uuid AND seq = ${current}`)
          return rows[0]?.part ?? null
        })
        if (piece === null || piece.byteLength !== length) {
          // Removed between the check and the read, which is a sweep
          // finishing under a download. The response is already under way,
          // so the honest thing left is to end it as an error rather than
          // close it short and let the browser believe it was whole.
          controller.error(new Error(`artifact ${artifact.id} lost chunk ${current} while it was being read`))
          return
        }
        controller.enqueue(new Uint8Array(piece.buffer, piece.byteOffset, piece.byteLength))
        seq++
      },
    }, { highWaterMark: 1 })

    return { kind: 'stream', body, range }
  }

  async remove(db: Db, artifact: Pick<StoredArtifact, 'id' | 'locator'>): Promise<void> {
    // A locator that is not this store's own shape is not deleted by guessing
    // at what it meant. Nothing was written under it here, so there is
    // nothing here to remove.
    if (!locatesItself(artifact)) return
    await db.execute(sql`DELETE FROM artifact_chunks WHERE artifact_id = ${artifact.id}::uuid`)
  }
}
