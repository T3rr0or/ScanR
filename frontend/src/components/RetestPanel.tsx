/**
 * RetestPanel — re-run the check behind a finding and show what it concluded.
 *
 * The remediation loop: a client says "fixed", and this answers "verified" or
 * "no, still there" without re-running the whole scan.
 *
 * "Inconclusive" is shown as prominently as the other verdicts on purpose. It
 * means the host did not answer, which is *not* remediation — presenting it
 * quietly next to "resolved" is how a live vulnerability gets a ticket closed.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, HelpCircle, RefreshCw, XCircle } from "lucide-react";

import {
  type FindingRetest,
  type RetestVerdict,
  findingsApi,
} from "@/api/findings";

const VERDICT: Record<RetestVerdict, { label: string; color: string; icon: typeof CheckCircle2 }> = {
  resolved: { label: "Resolved", color: "var(--sev-low, #22c55e)", icon: CheckCircle2 },
  still_present: { label: "Still present", color: "var(--sev-high, #f97316)", icon: XCircle },
  inconclusive: { label: "Inconclusive", color: "var(--sev-medium, #eab308)", icon: HelpCircle },
};

function fmt(ts: string | null): string {
  if (!ts) return "";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString();
}

export function VerdictBadge({ verdict }: { verdict: RetestVerdict }) {
  const v = VERDICT[verdict];
  if (!v) return null;
  const Icon = v.icon;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        fontSize: 10.5,
        color: v.color,
        border: `1px solid ${v.color}`,
        borderRadius: 3,
        padding: "1px 5px",
        whiteSpace: "nowrap",
      }}
    >
      <Icon size={10} />
      {v.label}
    </span>
  );
}

function RetestRow({ r }: { r: FindingRetest }) {
  const pending = r.status === "pending" || r.status === "running";
  return (
    <div style={{ borderTop: "1px solid var(--border)", padding: "7px 0", fontSize: 11.5 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 7, flexWrap: "wrap" }}>
        {pending ? (
          <span style={{ display: "inline-flex", alignItems: "center", gap: 4, color: "var(--text-3)" }}>
            <RefreshCw size={10} className="spin" /> {r.status}…
          </span>
        ) : r.verdict ? (
          <VerdictBadge verdict={r.verdict} />
        ) : (
          <span style={{ color: "var(--sev-high)", fontSize: 10.5 }}>Failed</span>
        )}
        <span style={{ color: "var(--text-3)", fontSize: 10.5 }}>
          {fmt(r.finished_at ?? r.created_at)}
        </span>
      </div>
      {(r.evidence || r.error) && (
        <pre
          style={{
            margin: "5px 0 0",
            padding: "6px 8px",
            background: "var(--bg-3)",
            borderRadius: 3,
            fontSize: 10.5,
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
            color: r.error ? "var(--sev-high)" : "var(--text-2)",
            maxHeight: 160,
            overflowY: "auto",
          }}
        >
          {r.error ?? r.evidence}
        </pre>
      )}
    </div>
  );
}

export default function RetestPanel({ findingId }: { findingId: string }) {
  const qc = useQueryClient();

  const { data: retests = [] } = useQuery({
    queryKey: ["finding-retests", findingId],
    queryFn: () => findingsApi.retests(findingId),
    // While one is in flight the worker owns the outcome, so poll until it lands.
    refetchInterval: (q) => {
      const rows = q.state.data as FindingRetest[] | undefined;
      const busy = rows?.some((r) => r.status === "pending" || r.status === "running");
      return busy ? 3000 : false;
    },
  });

  const mut = useMutation({
    mutationFn: () => findingsApi.retest(findingId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["finding-retests", findingId] });
      qc.invalidateQueries({ queryKey: ["findings"] });
    },
  });

  const running = retests.some((r) => r.status === "pending" || r.status === "running");
  const error = mut.error instanceof Error ? mut.error.message : null;

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
        <button
          className="btn btn-ghost btn-sm"
          disabled={running || mut.isPending}
          onClick={() => mut.mutate()}
          title="Re-run only this finding's check against the same host"
        >
          <RefreshCw size={11} /> {running ? "Retesting…" : "Retest"}
        </button>
        {retests.length === 0 && (
          <span style={{ fontSize: 11, color: "var(--text-3)" }}>Never retested</span>
        )}
      </div>

      {error && (
        <div style={{ fontSize: 11, color: "var(--sev-high)", marginBottom: 6 }}>{error}</div>
      )}

      {retests.map((r) => (
        <RetestRow key={r.id} r={r} />
      ))}
    </div>
  );
}
