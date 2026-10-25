"use client";

import { useState } from "react";
import { mutate, query, useApi } from "@/lib/api";
import { bytes } from "@/lib/format";
import { useSessionContext } from "@/components/session";
import { may } from "@/lib/roles";
import {
  CloseAccount,
  Deleting,
  ExportCard,
  Fact,
  Said,
  Sessions,
  saidWrong,
  type Deletion,
} from "@/components/exits";
import {
  Button,
  Card,
  CardSkeleton,
  Field,
  LinkButton,
  Loaded,
  Page,
  When,
  inputClass,
} from "@/components/ui";
import { useStartChoice } from "@/lib/start-choice";
import { optionFor } from "@/lib/start";

/* -------------------------------------------------------------------------
 * Shapes, matched to what the routes actually return.
 * ---------------------------------------------------------------------- */

interface Settings {
  slug: string;
  name: string;
  githubLogin: string | null;
  plan: string;
  createdAt: string;
  suspended: boolean;
  suspendedReason: string | null;
  counts: {
    members: number;
    repositories: number;
    environments: number;
    openInvitations: number;
  };
  deletion: Deletion | null;
  exportRetentionDays: number;
}

interface ArtifactStorage {
  enabled: boolean;
  retentionDays: number;
  usedBytes: number;
  kept: number;
  quotaBytes: number;
  minRetentionDays: number;
  maxRetentionDays: number;
}

interface BillingContact {
  contact: { email: string; name: string | null; updatedBy: string; updatedAt: string } | null;
  onFileWithStripe: string | null;
  hasCustomer: boolean;
}

/* -------------------------------------------------------------------------
 * Small pieces
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * The organization
 * ---------------------------------------------------------------------- */

function Organization({
  settings,
  csrf,
  mayEdit,
  onSaved,
}: {
  settings: Settings;
  csrf: string;
  mayEdit: boolean;
  onSaved: () => void;
}) {
  const [name, setName] = useState(settings.name);
  const [busy, setBusy] = useState(false);
  const [said, setSaid] = useState<{ tone: "ok" | "bad"; text: string } | null>(null);

  const changed = name.trim() !== settings.name && name.trim().length > 0;

  return (
    <Card
      title="Organization"
      note={
        mayEdit
          ? "The name is what people see. The identifier is what links and commands use, and it does not change."
          : "Changing the name needs owner or admin."
      }
    >
      <div className="space-y-5 px-4 py-4">
        <dl className="grid grid-cols-2 gap-x-4 gap-y-4 sm:grid-cols-4">
          <Fact label="Identifier">
            <span className="font-mono text-[12px]">{settings.slug}</span>
          </Fact>
          <Fact label="Plan">{settings.plan}</Fact>
          <Fact label="People">{settings.counts.members}</Fact>
          <Fact label="Repositories">{settings.counts.repositories}</Fact>
        </dl>

        {settings.suspended ? (
          <div className="rounded-md border border-[rgba(138,90,0,0.3)] bg-[rgba(138,90,0,0.06)] px-3.5 py-3">
            <p className="text-[13px] font-medium text-ink">
              This organization cannot create anything new
            </p>
            <p className="mt-1 text-[12px] leading-5 text-muted">
              What is already running keeps running and can still be read.
            </p>
            {/* The reason on its own line rather than welded to the sentence
                above it. It is a value somebody typed, or the phrase a deletion
                writes, and neither ends in a full stop, so joining them read as
                "deletion requested What is already running". */}
            <p className="mt-1 text-[12px] leading-5 text-dim">
              Reason: {settings.suspendedReason ?? "none was recorded"}.
            </p>
          </div>
        ) : null}

        {mayEdit ? (
          <form
            className="flex flex-wrap items-end gap-3"
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              setSaid(null);
              try {
                await mutate("org.rename", { name: name.trim() }, csrf);
                setSaid({ tone: "ok", text: "Saved." });
                onSaved();
              } catch (err) {
                setSaid({ tone: "bad", text: saidWrong(err) });
              } finally {
                setBusy(false);
              }
            }}
          >
            <div className="w-full max-w-[320px]">
              <Field label="Name">
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  maxLength={100}
                  className={inputClass}
                />
              </Field>
            </div>
            <Button type="submit" variant="primary" disabled={!changed} busy={busy}>
              Save
            </Button>
            {said ? <Said tone={said.tone}>{said.text}</Said> : null}
          </form>
        ) : (
          <Fact label="Name">{settings.name}</Fact>
        )}
      </div>
    </Card>
  );
}

/* -------------------------------------------------------------------------
 * How you chose to start
 *
 * The one per person thing on a page of per organization things, and said to
 * be: the answer lives in this browser, for this organization, and changing it
 * is reopening the question. Without this card the question was asked once and
 * could never be found again, which makes a remembered answer a trap.
 * ---------------------------------------------------------------------- */

function StartCard({ orgId }: { orgId: string }) {
  const { choice, ready } = useStartChoice(orgId);
  const current =
    !ready || choice === null
      ? "Not answered yet"
      : choice === "skipped"
        ? "Skipped for now"
        : optionFor(choice).title;
  return (
    <Card
      title="Getting started"
      note="How you said you wanted to start, which decides the next step the console shows. Remembered in this browser, for you."
    >
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-4">
        <dl>
          <Fact label="Your answer">{current}</Fact>
        </dl>
        <LinkButton href="/start" variant="secondary">
          {choice === null || choice === "skipped" ? "Answer it" : "Change"}
        </LinkButton>
      </div>
    </Card>
  );
}

/* -------------------------------------------------------------------------
 * Artifact storage
 * ---------------------------------------------------------------------- */

/**
 * Whether a run's recordings leave the machine that made them.
 *
 * Off until somebody turns it on, because a recording is the application as
 * the runner drove it: every page it showed, test data and all. The control
 * plane refuses an upload until this says yes, and the switch is written to
 * the audit log either way.
 */
function ArtifactStorageCard({ csrf, mayEdit }: { csrf: string; mayEdit: boolean }) {
  const state = useApi<ArtifactStorage>(() => query("org.artifactStorage"), []);
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [days, setDays] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [said, setSaid] = useState<{ tone: "ok" | "bad"; text: string } | null>(null);

  return (
    <Card
      title="Artifact storage"
      note="Whether the runner uploads each workflow's video, trace and screenshot here after a run, so a run's page can show why it failed after the machine that ran it is gone."
    >
      <Loaded state={state} framed skeleton={<CardSkeleton count={1} />}>
        {(loaded) => {
          const on = enabled ?? loaded.enabled;
          const retention = days ?? String(loaded.retentionDays);
          const n = Number(retention);
          const validDays =
            Number.isInteger(n) && n >= loaded.minRetentionDays && n <= loaded.maxRetentionDays;
          const changed = on !== loaded.enabled || (validDays && n !== loaded.retentionDays);

          return (
            <div className="space-y-4 px-4 py-4">
              <dl className="grid grid-cols-2 gap-4 sm:grid-cols-3">
                <Fact label="Uploads">{loaded.enabled ? "On" : "Off"}</Fact>
                <Fact label="Kept for">{loaded.retentionDays} days</Fact>
                <Fact label="Used">
                  {bytes(loaded.usedBytes)} of {bytes(loaded.quotaBytes)}, {loaded.kept} file
                  {loaded.kept === 1 ? "" : "s"}
                </Fact>
              </dl>

              <p className="max-w-[72ch] text-[12.5px] leading-5 text-muted">
                A recording shows whatever the application showed the runner, test data included.
                While this is off, recordings stay on the machine that ran them. A runner started
                with <span className="font-mono text-[11.5px]">AF_ARTIFACTS=local</span> keeps its
                own whatever this says. Turning it off stops new uploads, and a new retention
                applies to files stored after it changes: files already kept are dropped when the
                time they were stored with runs out.
              </p>

              {mayEdit ? (
                <form
                  className="flex flex-wrap items-end gap-x-6 gap-y-3"
                  onSubmit={async (e) => {
                    e.preventDefault();
                    if (!validDays) return;
                    setBusy(true);
                    setSaid(null);
                    try {
                      await mutate("org.setArtifactStorage", { enabled: on, retentionDays: n }, csrf);
                      setSaid({ tone: "ok", text: "Saved, and recorded in the audit log." });
                      setEnabled(null);
                      setDays(null);
                      state.reload();
                    } catch (err) {
                      setSaid({ tone: "bad", text: saidWrong(err) });
                    } finally {
                      setBusy(false);
                    }
                  }}
                >
                  <label className="flex min-h-11 items-center gap-2.5 text-[13.5px] text-ink">
                    <input
                      type="checkbox"
                      checked={on}
                      onChange={(e) => setEnabled(e.target.checked)}
                      className="h-4 w-4 accent-[#101010]"
                    />
                    Upload run recordings
                  </label>
                  <div className="w-full max-w-[160px]">
                    <Field label={`Keep for (days, ${loaded.minRetentionDays} to ${loaded.maxRetentionDays})`}>
                      <input
                        type="number"
                        inputMode="numeric"
                        min={loaded.minRetentionDays}
                        max={loaded.maxRetentionDays}
                        step={1}
                        value={retention}
                        onChange={(e) => setDays(e.target.value)}
                        className={inputClass}
                        aria-invalid={!validDays}
                      />
                    </Field>
                  </div>
                  <Button type="submit" variant="primary" disabled={!changed || !validDays} busy={busy}>
                    Save
                  </Button>
                </form>
              ) : (
                <p className="text-[12px] leading-5 text-dim">
                  An owner or an administrator can change this.
                </p>
              )}

              {said ? <Said tone={said.tone}>{said.text}</Said> : null}
            </div>
          );
        }}
      </Loaded>
    </Card>
  );
}

/* -------------------------------------------------------------------------
 * The billing contact
 * ---------------------------------------------------------------------- */

function BillingContactCard({ csrf }: { csrf: string }) {
  const state = useApi<BillingContact>(() => query("org.billingContact"), []);
  const [email, setEmail] = useState<string | null>(null);
  const [name, setName] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [said, setSaid] = useState<{ tone: "ok" | "bad"; text: string } | null>(null);

  return (
    <Card
      title="Billing contact"
      note="Where invoices and payment notices go. This is not anybody's sign-in address."
    >
      <Loaded state={state} framed skeleton={<CardSkeleton count={1} />}>
        {(loaded) => {
          const current = email ?? loaded.contact?.email ?? "";
          const currentName = name ?? loaded.contact?.name ?? "";
          const disagrees =
            loaded.hasCustomer &&
            loaded.contact !== null &&
            loaded.onFileWithStripe !== null &&
            loaded.onFileWithStripe !== loaded.contact.email;

          return (
            <div className="space-y-4 px-4 py-4">
              {disagrees ? (
                <div className="rounded-md border border-[rgba(138,90,0,0.3)] bg-[rgba(138,90,0,0.06)] px-3.5 py-3">
                  <p className="text-[13px] font-medium text-ink">
                    Invoices are still going to a different address
                  </p>
                  <p className="mt-1 text-[12px] leading-5 text-muted">
                    Stripe has{" "}
                    <span className="font-mono text-[11.5px]">{loaded.onFileWithStripe}</span> on
                    file. Save the address again to send it across.
                  </p>
                </div>
              ) : null}

              <form
                className="flex flex-wrap items-end gap-3"
                onSubmit={async (e) => {
                  e.preventDefault();
                  setBusy(true);
                  setSaid(null);
                  try {
                    const saved = await mutate<{ pushedToStripe: boolean; note: string | null }>(
                      "org.setBillingContact",
                      { email: current.trim(), name: currentName.trim() || undefined },
                      csrf,
                    );
                    setSaid({
                      tone: "ok",
                      text: saved.pushedToStripe
                        ? "Saved, and sent to Stripe."
                        : (saved.note ?? "Saved."),
                    });
                    state.reload();
                  } catch (err) {
                    setSaid({ tone: "bad", text: saidWrong(err) });
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                <div className="w-full max-w-[320px]">
                  <Field label="Email address">
                    <input
                      type="email"
                      value={current}
                      onChange={(e) => setEmail(e.target.value)}
                      className={inputClass}
                      placeholder="accounts@yourcompany.com"
                    />
                  </Field>
                </div>
                <div className="w-full max-w-[240px]">
                  <Field label="Name (optional)">
                    <input
                      value={currentName}
                      onChange={(e) => setName(e.target.value)}
                      className={inputClass}
                      placeholder="Accounts payable"
                    />
                  </Field>
                </div>
                <Button
                  type="submit"
                  variant="primary"
                  disabled={current.trim().length < 3}
                  busy={busy}
                >
                  Save
                </Button>
              </form>

              {said ? <Said tone={said.tone}>{said.text}</Said> : null}
              {loaded.contact ? (
                <p className="text-[12px] leading-5 text-dim">
                  Last changed by {loaded.contact.updatedBy},{" "}
                  <When value={loaded.contact.updatedAt} />.
                </p>
              ) : null}
            </div>
          );
        }}
      </Loaded>
    </Card>
  );
}

/* -------------------------------------------------------------------------
 * The page
 * ---------------------------------------------------------------------- */

export default function SettingsPage() {
  const session = useSessionContext();
  const state = useApi<Settings>(() => query("org.settings"), []);
  const csrf = session.data?.csrfToken ?? "";
  const role = session.data?.role ?? null;

  const mayEditSettings = may(role, "organization.settings");
  const mayBill = may(role, "billing.manage");
  const maySessions = may(role, "sessions.manage");
  const mayExport = may(role, "data.export");
  const mayDelete = may(role, "organization.delete");

  return (
    <Page
      title="Settings"
      lede="Everything about this organization that is not about one repository: who can reach it, where the bills go, and how to leave."
    >
      <Loaded state={state} framed skeleton={<CardSkeleton count={3} />}>
        {(settings) => (
          <div className="space-y-6">
            <Organization
              settings={settings}
              csrf={csrf}
              mayEdit={mayEditSettings}
              onSaved={state.reload}
            />
            {session.data?.orgId ? <StartCard orgId={session.data.orgId} /> : null}
            <ArtifactStorageCard csrf={csrf} mayEdit={mayEditSettings} />
            {mayBill ? <BillingContactCard csrf={csrf} /> : null}
            {maySessions ? <Sessions csrf={csrf} /> : null}
            {mayExport ? <ExportCard csrf={csrf} slug={settings.slug} /> : null}
            <Deleting
              org={settings}
              csrf={csrf}
              mayDelete={mayDelete}
              onChanged={state.reload}
            />
            <CloseAccount csrf={csrf} label={session.data?.label ?? ""} />
          </div>
        )}
      </Loaded>
    </Page>
  );
}
