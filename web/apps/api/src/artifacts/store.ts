// Where an artifact's bytes live, as an interface with more than one answer.
//
// 0001 put the bytes in object storage behind a signed URL, and that is still
// the destination: a recording of a customer's application is the most
// sensitive thing this system holds, and the fewer copies of it there are the
// smaller that problem is. The first implementation is Postgres anyway,
// because it is the one store every installation already has, and a feature
// that needs an operator to create a bucket before it works is a feature that
// does not work on the day it ships.
//
// So everything that touches bytes goes through this interface, and nothing
// else does:
//
//   - The upload route hands a verified buffer to `put`, which returns the
//     locator the row records.
//   - The download route calls `open`, which answers with a stream, or with a
//     redirect for a backend that can mint a short lived URL of its own. A
//     store that serves bytes through this process and one that sends the
//     browser elsewhere are one route.
//   - The retention sweep calls `remove`.
//
// Every row records which backend wrote it, in `artifacts.backend`, so moving
// to a second backend is a new value for that column and new uploads going to
// it, and the rows already written stay readable where they are.

import type { Db } from '@antifailure/db'
import type { ByteRange } from './policy.ts'

/** Where `put` wrote an object. */
export interface StoredObject {
  /** The locator, which `artifacts.storage_key` records. */
  locator: string
  sizeBytes: number
}

/** What `put` is told about the object it is writing. */
export interface PutTarget {
  orgId: string
  artifactId: string
  /** When retention may remove it, recorded beside the bytes where the store
   *  can. */
  expiresAt: Date
}

/** The object `open` and `remove` act on, as the row records it. */
export interface StoredArtifact {
  id: string
  orgId: string
  locator: string
  sizeBytes: number
  contentType: string
}

/**
 * What `open` answers.
 *
 * `stream` is the bytes, from `range.start` to `range.end` inclusive, or the
 * whole object when there was no range. `redirect` is a URL the browser fetches
 * itself, which a store can answer for only when it can make one that expires
 * and that names this object and nothing else. `missing` is a row whose bytes
 * are not where it says, which the route answers 410 rather than 500, because
 * a fixture row or a half finished sweep is a fact about the data and not a
 * failure of the server.
 */
export type OpenedArtifact =
  | { kind: 'stream'; body: ReadableStream<Uint8Array>; range: ByteRange | null }
  | { kind: 'redirect'; url: string }
  | { kind: 'missing' }

/**
 * A scope the store reads through, bound to the artifact's own tenant.
 *
 * A function rather than a connection, so the store opens one short
 * transaction per piece it reads instead of holding one open for as long as a
 * browser takes to watch a video. The pool has ten connections, and a
 * download that held one for a minute would be a tenth of the control plane.
 */
export type TenantScope = <T>(fn: (db: Db) => Promise<T>) => Promise<T>

export interface ArtifactStore {
  /** The value `artifacts.backend` records for an object this store holds. */
  readonly backend: string
  /**
   * Writes an object, inside the caller's transaction where the store is the
   * database, so that a row and its bytes commit or fail together.
   */
  put(db: Db, target: PutTarget, bytes: Uint8Array): Promise<StoredObject>
  /** Reads an object, or the range of it a video element asked for. */
  open(scope: TenantScope, artifact: StoredArtifact, range: ByteRange | null): Promise<OpenedArtifact>
  /**
   * Removes an object. Removing one that is already gone succeeds, because the
   * sweep retries and a second pass over a removed object is the ordinary case.
   */
  remove(db: Db, artifact: Pick<StoredArtifact, 'id' | 'locator'>): Promise<void>
}

/**
 * The stores this process can read, by backend, and the one it writes to.
 *
 * Reading is by the row's own backend and writing is by configuration, which
 * is what lets a deployment change where new artifacts go without stranding the
 * old ones. A row naming a backend this process was not given is answered as
 * missing rather than read through some other store.
 */
export class ArtifactStores {
  readonly writer: ArtifactStore
  private readonly byBackend: Map<string, ArtifactStore>

  constructor(writer: ArtifactStore, readers: ArtifactStore[] = []) {
    this.writer = writer
    this.byBackend = new Map([writer, ...readers].map((s) => [s.backend, s]))
  }

  reader(backend: string): ArtifactStore | null {
    return this.byBackend.get(backend) ?? null
  }

  backends(): string[] {
    return [...this.byBackend.keys()].sort()
  }
}
