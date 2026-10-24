// What an artifact may be, before anything about it is stored.
//
// Every rule here is a pure function of the request, so the upload route can
// refuse before it reads a byte of the body and the tests can name each refusal
// without a database. The route, the download path and the console all read
// their answers from this one file, because three copies of "which types may a
// video be" are three chances to serve something as a type it is not.

const MiB = 1024 * 1024

/** The evidence the runner records for a workflow, and nothing else. */
export const ARTIFACT_KINDS = ['video', 'trace', 'screenshot'] as const
export type ArtifactKind = (typeof ARTIFACT_KINDS)[number]

export interface KindPolicy {
  /** The content types an artifact of this kind may declare. */
  contentTypes: readonly string[]
  /** The most bytes one artifact of this kind may hold. */
  maxBytes: number
  /** The file extension a download is named with, by content type. */
  extensions: Readonly<Record<string, string>>
  /** Whether a browser should show it rather than save it. */
  inline: boolean
  /** Why the number is what it is, for whoever changes it. */
  reason: string
}

export const KIND_POLICIES: Readonly<Record<ArtifactKind, KindPolicy>> = {
  video: {
    contentTypes: ['video/webm', 'video/mp4'],
    maxBytes: 64 * MiB,
    extensions: { 'video/webm': 'webm', 'video/mp4': 'mp4' },
    inline: true,
    reason:
      'Playwright records a workflow at 800 by 450 in VP8, which is about a megabyte for every ten ' +
      'seconds of a busy page, and a workflow stops at forty steps. Sixty four megabytes is several ' +
      'times the longest honest recording, and is the same ceiling the website media library sets ' +
      'for a video.',
  },
  trace: {
    contentTypes: ['application/zip'],
    maxBytes: 64 * MiB,
    extensions: { 'application/zip': 'zip' },
    // A trace is opened with the Playwright trace viewer, not by the browser,
    // and a zip shown inline is a download anyway.
    inline: false,
    reason:
      'A Playwright trace is a zip of the DOM snapshots, the network log and a screenshot per action. ' +
      'Snapshots are text and compress well, so a forty step workflow is a few megabytes; the ' +
      'ceiling matches the video beside it so that a run is never kept with one and not the other.',
  },
  screenshot: {
    contentTypes: ['image/png', 'image/jpeg'],
    maxBytes: 8 * MiB,
    extensions: { 'image/png': 'png', 'image/jpeg': 'jpg' },
    inline: true,
    reason:
      'A full page PNG of a long page at device scale two is the largest a screenshot honestly gets, ' +
      'and that is a few megabytes. Eight leaves room and refuses a file that is not a screenshot.',
  },
}

export function isArtifactKind(value: unknown): value is ArtifactKind {
  return typeof value === 'string' && (ARTIFACT_KINDS as readonly string[]).includes(value)
}

/** The longest workflow name an artifact may carry, matching the column. */
export const MAX_WORKFLOW_CHARS = 500

/** A refusal, carrying the status and a code the engine branches on. */
export class ArtifactRefusal extends Error {
  readonly status: 400 | 403 | 404 | 409 | 411 | 413 | 415 | 422 | 429 | 503 | 507
  readonly code: string
  readonly retryAfterSeconds: number | null
  constructor(
    status: ArtifactRefusal['status'],
    code: string,
    message: string,
    retryAfterSeconds: number | null = null,
  ) {
    super(message)
    this.status = status
    this.code = code
    this.retryAfterSeconds = retryAfterSeconds
  }
}

/** What an upload declares about itself in its headers. */
export interface UploadDeclaration {
  kind: ArtifactKind
  workflow: string
  step: number | null
  contentType: string
  sizeBytes: number
  sha256: string
}

const SHA256_HEX = /^[0-9a-f]{64}$/

/**
 * Reads an upload's headers into a declaration, or refuses.
 *
 * Content-Length is required rather than read from the body afterwards. The
 * route reserves memory for the body before it reads one, and a body whose
 * length is unknown is a body that cannot be reserved for; the engine always
 * knows the size of a file it is about to send.
 *
 * The workflow travels percent encoded, because a header is Latin-1 on the
 * wire and a workflow is named in whatever language its author wrote it in.
 */
export function readDeclaration(header: (name: string) => string | undefined): UploadDeclaration {
  const kind = header('x-artifact-kind')?.trim() ?? ''
  if (!isArtifactKind(kind)) {
    throw new ArtifactRefusal(400, 'kind', `x-artifact-kind must be one of ${ARTIFACT_KINDS.join(', ')}.`)
  }
  const policy = KIND_POLICIES[kind]

  let workflow: string
  try {
    workflow = decodeURIComponent(header('x-artifact-workflow') ?? '').normalize('NFC').trim()
  } catch {
    throw new ArtifactRefusal(400, 'workflow', 'x-artifact-workflow is not valid percent encoded UTF-8.')
  }
  if (workflow === '' || workflow.length > MAX_WORKFLOW_CHARS) {
    throw new ArtifactRefusal(
      400, 'workflow', `x-artifact-workflow must name the workflow, in at most ${MAX_WORKFLOW_CHARS} characters.`,
    )
  }
  // Control characters are refused rather than stripped, because a name that
  // changes on the way in is a name that no longer matches the verdict.
  if (/[\u0000-\u001f\u007f]/.test(workflow)) {
    throw new ArtifactRefusal(400, 'workflow', 'x-artifact-workflow contains a control character.')
  }

  const rawStep = header('x-artifact-step')?.trim()
  let step: number | null = null
  if (rawStep !== undefined && rawStep !== '') {
    if (!/^\d{1,6}$/.test(rawStep)) {
      throw new ArtifactRefusal(400, 'step', 'x-artifact-step must be a whole number.')
    }
    step = Number(rawStep)
  }

  const contentType = (header('content-type') ?? '').split(';')[0]!.trim().toLowerCase()
  if (!policy.contentTypes.includes(contentType)) {
    throw new ArtifactRefusal(
      415, 'content_type', `A ${kind} must be ${policy.contentTypes.join(' or ')}, and this is ${contentType || 'unnamed'}.`,
    )
  }

  const rawLength = header('content-length')?.trim() ?? ''
  if (!/^\d{1,12}$/.test(rawLength)) {
    throw new ArtifactRefusal(411, 'length', 'An upload must declare its Content-Length.')
  }
  const sizeBytes = Number(rawLength)
  if (sizeBytes < 1) throw new ArtifactRefusal(400, 'length', 'An upload must not be empty.')
  if (sizeBytes > policy.maxBytes) {
    throw new ArtifactRefusal(
      413, 'too_large', `A ${kind} may be at most ${policy.maxBytes} bytes, and this one is ${sizeBytes}.`,
    )
  }

  const sha256 = header('x-artifact-sha256')?.trim().toLowerCase() ?? ''
  if (!SHA256_HEX.test(sha256)) {
    throw new ArtifactRefusal(400, 'digest', 'x-artifact-sha256 must be the SHA-256 of the body, in hex.')
  }
  return { kind, workflow, step, contentType, sizeBytes, sha256 }
}

/**
 * Whether the bytes are what the content type says they are.
 *
 * The bytes are served back to a browser, from the console's own origin. A file
 * declared image/png that is really HTML is the oldest way to turn an upload
 * into script, and nosniff only helps if the declared type was true. So each
 * accepted type is checked against the signature every file of that type
 * starts with, and a mismatch is refused rather than stored.
 */
export function bytesMatchType(bytes: Uint8Array, contentType: string): boolean {
  const starts = (...sig: number[]) => sig.every((b, i) => bytes[i] === b)
  switch (contentType) {
    case 'video/webm':
      return starts(0x1a, 0x45, 0xdf, 0xa3) // EBML header
    case 'video/mp4':
      // ISO base media: a box size, then the four characters ftyp.
      return bytes.length >= 12 && bytes[4] === 0x66 && bytes[5] === 0x74 && bytes[6] === 0x79 && bytes[7] === 0x70
    case 'application/zip':
      return starts(0x50, 0x4b, 0x03, 0x04) || starts(0x50, 0x4b, 0x05, 0x06) // local header, or empty archive
    case 'image/png':
      return starts(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)
    case 'image/jpeg':
      return starts(0xff, 0xd8, 0xff)
    default:
      return false
  }
}

/**
 * The Content-Disposition a download carries.
 *
 * The filename is built from the workflow and the kind, never from anything the
 * uploader called the file, and is ASCII only in the plain parameter with the
 * real name in the RFC 6266 extended one, so a workflow named in another script
 * downloads under its own name and a quote in it cannot end the header early.
 */
export function contentDisposition(kind: ArtifactKind, workflow: string, contentType: string): string {
  const policy = KIND_POLICIES[kind]
  const extension = policy.extensions[contentType] ?? 'bin'
  const base = `${workflow || 'run'}-${kind}`
  const ascii = base.replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 120) || kind
  const encoded = encodeURIComponent(`${base}.${extension}`).replace(/['()*]/g, (c) =>
    `%${c.charCodeAt(0).toString(16).toUpperCase()}`)
  const disposition = policy.inline ? 'inline' : 'attachment'
  return `${disposition}; filename="${ascii}.${extension}"; filename*=UTF-8''${encoded}`
}

/** A byte range a download was asked for, inclusive at both ends. */
export interface ByteRange {
  start: number
  end: number
}

/**
 * Reads a Range header against an object's size, the subset a video element
 * sends: one range, `bytes=a-b`, `bytes=a-` or `bytes=-n`. Null when there is
 * no header, and a RangeError for one that cannot be satisfied, which the
 * route answers 416.
 */
export function parseRange(value: string | undefined, size: number): ByteRange | null {
  if (!value) return null
  const match = /^bytes=(\d*)-(\d*)$/.exec(value.trim())
  if (!match || (!match[1] && !match[2])) throw new RangeError('not a single byte range')
  let start: number
  let end: number
  if (!match[1]) {
    const suffix = Number(match[2])
    if (!Number.isSafeInteger(suffix) || suffix < 1) throw new RangeError('an empty suffix')
    start = Math.max(0, size - suffix)
    end = size - 1
  } else {
    start = Number(match[1])
    end = match[2] ? Number(match[2]) : size - 1
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start >= size || start > end) {
      throw new RangeError('outside the object')
    }
    end = Math.min(end, size - 1)
  }
  return { start, end }
}
