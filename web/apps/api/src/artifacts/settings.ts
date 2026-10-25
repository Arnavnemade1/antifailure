// Whether this organization keeps the recordings its runs make, and for how
// long.
//
// Spread into the org router beside the display name and the billing contact,
// for the reason routers/enterprise.ts gives: one router per noun, so the
// console asks one place about one row.
//
// Reading is open to anyone who can see environments, because a member who
// opens a run and finds no artifacts needs to be able to learn that storage is
// off rather than suspect a bug. Changing it needs organization.settings, and
// every change is audited with what it was and what it became, because this is
// the switch that decides whether recordings of the application leave the
// machines the runs happen on.

import { z } from 'zod'
import { sql } from '@antifailure/db'
import { orgProcedure, audit, type OrgContext } from '../trpc.ts'
import { DEFAULT_ORG_QUOTA_BYTES } from './routes.ts'

export const MIN_RETENTION_DAYS = 1
export const MAX_RETENTION_DAYS = 365

interface SettingsRow extends Record<string, unknown> {
  enabled: boolean
  retention_days: number
  used: string
  kept: string
}

export const artifactSettings = {
  /** The organization's artifact storage, as the settings page shows it. */
  artifactStorage: orgProcedure('environments.view').query(async ({ ctx }) => {
    const c = ctx as OrgContext
    return c.pool.withTenant(c.tenant, async (db) => {
      const rows = await db.execute<SettingsRow>(sql`
        SELECT o.artifact_uploads_enabled AS enabled,
               o.artifact_retention_days AS retention_days,
               (SELECT coalesce(sum(a.size_bytes), 0) FROM artifacts a WHERE a.retained)::text AS used,
               (SELECT count(*) FROM artifacts a WHERE a.retained)::text AS kept
        FROM organizations o WHERE o.id = ${c.actor.orgId}::uuid`)
      const row = rows[0]
      return {
        enabled: row?.enabled ?? false,
        retentionDays: row?.retention_days ?? 30,
        // Numbers rather than the driver's strings, for the reason
        // runs.artifacts gives: a client formatting a string by coercion
        // gets NaN from the next field it treats the same way.
        usedBytes: Number(row?.used ?? 0),
        kept: Number(row?.kept ?? 0),
        quotaBytes: c.artifactQuotaBytes ?? DEFAULT_ORG_QUOTA_BYTES,
        minRetentionDays: MIN_RETENTION_DAYS,
        maxRetentionDays: MAX_RETENTION_DAYS,
      }
    })
  }),

  /**
   * Turns artifact storage on or off, and sets how long artifacts are kept.
   *
   * Turning it off stops new uploads and leaves what is stored where it is,
   * to expire on its own schedule. Deleting a team's evidence because
   * somebody changed a setting is the kind of side effect a setting should
   * not have; the retention is what removes it.
   *
   * A new retention applies to artifacts stored from now on. One already
   * stored keeps the expiry it was stored with, so shortening the retention
   * cannot reach back and remove evidence somebody is relying on today.
   */
  setArtifactStorage: orgProcedure('organization.settings')
    .input(z.object({
      enabled: z.boolean(),
      retentionDays: z.number().int().min(MIN_RETENTION_DAYS).max(MAX_RETENTION_DAYS),
    }))
    .mutation(async ({ ctx, input }) => {
      const c = ctx as OrgContext
      return c.pool.withTenant(c.tenant, async (db) => {
        const before = await db.execute<{ enabled: boolean; retention_days: number }>(sql`
          SELECT artifact_uploads_enabled AS enabled, artifact_retention_days AS retention_days
          FROM organizations WHERE id = ${c.actor.orgId}::uuid FOR UPDATE`)
        const was = before[0]
        await db.execute(sql`
          UPDATE organizations
          SET artifact_uploads_enabled = ${input.enabled},
              artifact_retention_days = ${input.retentionDays},
              updated_at = ${c.clock.now().toISOString()}
          WHERE id = ${c.actor.orgId}::uuid`)
        const switched = !was || was.enabled !== input.enabled
        if (switched || was.retention_days !== input.retentionDays) {
          await audit(db, c, {
            // Named for what changed. A retention edit on storage that was
            // already on is not somebody turning storage on, and an audit
            // reader filtering for the switch must not find it.
            action: !switched
              ? 'organization.artifacts_retention_changed'
              : input.enabled ? 'organization.artifacts_enabled' : 'organization.artifacts_disabled',
            targetType: 'organization',
            targetId: c.actor.orgId,
            detail: {
              enabled: { from: was?.enabled ?? false, to: input.enabled },
              retentionDays: { from: was?.retention_days ?? 30, to: input.retentionDays },
            },
          })
        }
        return { enabled: input.enabled, retentionDays: input.retentionDays }
      })
    }),
}
