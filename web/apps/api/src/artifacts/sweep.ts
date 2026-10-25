// Retention, carried out.
//
// security.ts used to say that nothing in this schema expires on a schedule
// and that artifacts carry a retained flag nothing clears. An artifact now
// carries its expiry from the moment it is written, and this removes the bytes
// of every artifact past it and clears the flag, leaving the row so that a run
// still says it had a video that was not kept rather than rendering a gap.
//
// It runs as antifailure_sweeper, through withExpirySweeper, because a sweep is
// nobody's request and has no tenant; migration 0052 gives that role the
// columns this reads and the one it writes, on rows the database's own clock
// says are due, and nothing else. In particular it cannot read a byte of what
// it deletes.

import { sql, type Pool } from '@antifailure/db'
import type { ArtifactStores } from './store.ts'

/** How many artifacts one pass handles, so a backlog is a few passes rather
 *  than one transaction long enough to trip the statement timeout. */
export const SWEEP_BATCH = 200

export interface SweepResult {
  /** Artifacts whose bytes were removed and whose row now says so. */
  removed: number
  /**
   * Artifacts due for removal whose backend this process was not given. They
   * are left exactly as they are: marking one not retained while its bytes
   * still sit in a store nobody here can reach would be a row saying the
   * evidence is gone when it is not.
   */
  unreachable: number
}

export async function sweepExpiredArtifacts(
  pool: Pool,
  stores: ArtifactStores,
  batch: number = SWEEP_BATCH,
): Promise<SweepResult> {
  return pool.withExpirySweeper(async (db) => {
    const due = await db.execute<{ id: string; backend: string; storage_key: string }>(sql`
      SELECT id, backend, storage_key FROM artifacts
      WHERE retained AND expires_at <= now()
      ORDER BY expires_at
      LIMIT ${batch}`)
    let removed = 0
    let unreachable = 0
    for (const artifact of due) {
      const store = stores.reader(artifact.backend)
      if (!store) {
        unreachable++
        continue
      }
      await store.remove(db, { id: artifact.id, locator: artifact.storage_key })
      await db.execute(sql`UPDATE artifacts SET retained = false WHERE id = ${artifact.id}::uuid`)
      removed++
    }
    return { removed, unreachable }
  })
}
