/**
 * AttackPaths — ranked routes from the attacker's position to something that matters.
 *
 * Presented as ordered narratives rather than a force-directed graph on purpose:
 * a path is a *sequence*, and force layouts are poor at showing order — you end up
 * tracing edges by hand to answer "what happens first". The topology tab already
 * covers the spatial view; this one answers "how do they get in, and what do I fix
 * first".
 *
 * Inferred steps are visually distinct everywhere they appear. A report that blends
 * a hypothesis into a chain of observations costs the tester their credibility, so
 * the distinction is never dropped for tidiness.
 */
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowRight,
  Crown,
  DoorOpen,
  Key,
  MoveRight,
  Server,
  ShieldAlert,
  Sparkles,
  TrendingUp,
} from "lucide-react";
import { useState } from "react";

import {
  type AttackEdgeKind,
  type AttackNode,
  type AttackNodeKind,
  type AttackPath,
  attackPathsApi,
} from "@/api/attackPaths";

const SEV_COLOR: Record<string, string> = {
  critical: "var(--sev-critical, #f43f5e)",
  high: "var(--sev-high, #f97316)",
  medium: "var(--sev-medium, #eab308)",
  low: "var(--sev-low, #22c55e)",
  info: "var(--sev-info, #38bdf8)",
};

const KIND_ICON: Record<AttackEdgeKind, typeof DoorOpen> = {
  foothold: DoorOpen,
  credential_access: Key,
  lateral_movement: MoveRight,
  credential_reuse: Sparkles,
  privilege_escalation: TrendingUp,
  domain_compromise: Crown,
};

const KIND_LABEL: Record<AttackEdgeKind, string> = {
  foothold: "Initial access",
  credential_access: "Credential access",
  lateral_movement: "Lateral movement",
  credential_reuse: "Credential reuse",
  privilege_escalation: "Privilege escalation",
  domain_compromise: "Domain compromise",
};

const NODE_ICON: Record<AttackNodeKind, typeof Server> = {
  entry: DoorOpen,
  host: Server,
  credential: Key,
  domain: Crown,
};

function sevColor(sev: string): string {
  return SEV_COLOR[sev] ?? "var(--text-3)";
}

function InferredTag() {
  return (
    <span
      title="Reasoned from observed services, not demonstrated by the scan"
      style={{
        fontSize: 9.5,
        textTransform: "uppercase",
        letterSpacing: 0.4,
        padding: "1px 5px",
        borderRadius: 3,
        border: "1px dashed var(--text-3)",
        color: "var(--text-3)",
        whiteSpace: "nowrap",
      }}
    >
      inferred
    </span>
  );
}

function PathCard({
  path,
  rank,
  nodesById,
}: {
  path: AttackPath;
  rank: number;
  nodesById: Map<string, AttackNode>;
}) {
  return (
    <div
      style={{
        border: "1px solid var(--border)",
        borderLeft: `3px solid ${sevColor(path.severity)}`,
        borderRadius: 4,
        padding: "10px 12px",
        marginBottom: 10,
        background: "var(--bg-2)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8, flexWrap: "wrap" }}>
        <span style={{ fontSize: 11, color: "var(--text-3)", fontFamily: "var(--font-mono)" }}>
          #{rank}
        </span>
        <span style={{ fontSize: 12.5, fontWeight: 600 }}>{path.objective}</span>
        <span
          style={{
            fontSize: 10,
            textTransform: "uppercase",
            letterSpacing: 0.4,
            color: sevColor(path.severity),
          }}
        >
          {path.severity}
        </span>
        {path.inferred ? (
          <InferredTag />
        ) : (
          <span
            title="Every step in this chain is backed by a finding from this scan"
            style={{ fontSize: 9.5, textTransform: "uppercase", letterSpacing: 0.4, color: "var(--sev-low, #22c55e)" }}
          >
            confirmed
          </span>
        )}
        <span style={{ marginLeft: "auto", fontSize: 11, color: "var(--text-3)" }}>
          {path.length} step{path.length === 1 ? "" : "s"}
        </span>
      </div>

      <ol style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 5 }}>
        {path.steps.map((step, i) => {
          const Icon = KIND_ICON[step.kind];
          const target = nodesById.get(step.target);
          return (
            <li
              key={`${step.source}-${step.target}-${i}`}
              style={{ display: "flex", alignItems: "flex-start", gap: 7, fontSize: 11.5 }}
            >
              <Icon size={12} style={{ marginTop: 2, flexShrink: 0, color: sevColor(step.severity) }} />
              <div style={{ minWidth: 0 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                  <span style={{ color: "var(--text-3)", fontSize: 10.5 }}>{KIND_LABEL[step.kind]}</span>
                  <ArrowRight size={9} style={{ color: "var(--text-3)" }} />
                  <span style={{ fontWeight: 500 }}>{target?.label ?? step.target}</span>
                  {step.inferred && <InferredTag />}
                </div>
                <div style={{ color: "var(--text-2)", wordBreak: "break-word" }}>{step.label}</div>
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

export default function AttackPaths({ scanId }: { scanId: string }) {
  // Off by default, matching the API. The inference is credentials x hosts —
  // 92% of edges on a 1000-host scan — and no ranked path has ever used one.
  const [includeInferred, setIncludeInferred] = useState(false);

  const { data, isLoading, error } = useQuery({
    queryKey: ["attack-paths", scanId, includeInferred],
    queryFn: () => attackPathsApi.get(scanId, { includeInferred }),
  });

  if (isLoading) {
    return <div style={{ textAlign: "center", color: "var(--text-3)", padding: 40 }}>Loading…</div>;
  }
  if (error) {
    return (
      <div style={{ color: "var(--sev-high)", padding: 20, fontSize: 12 }}>
        Could not build the attack graph: {error instanceof Error ? error.message : String(error)}
      </div>
    );
  }
  if (!data) return null;

  const nodesById = new Map(data.nodes.map((n) => [n.id, n]));

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
        <div style={{ fontSize: 12, color: "var(--text-2)" }}>
          <strong>{data.summary.path_count}</strong> route
          {data.summary.path_count === 1 ? "" : "s"} to an objective
          {data.summary.path_count > 0 && (
            <>
              {" "}
              (<strong>{data.summary.confirmed_path_count}</strong> fully confirmed)
            </>
          )}{" "}
          across {data.summary.host_count} host{data.summary.host_count === 1 ? "" : "s"}
          {data.truncated && (
            <span
              style={{ color: "var(--sev-medium)", marginLeft: 8 }}
              title={`Graph trimmed for display: showing ${data.edges.length} of ${data.totals.edges} edges. Ranked routes are always complete.`}
            >
              (graph trimmed — routes are complete)
            </span>
          )}
        </div>
        <label
          style={{ marginLeft: "auto", fontSize: 11.5, color: "var(--text-2)", display: "flex", alignItems: "center", gap: 6 }}
          title="Credential reuse is reasoned from observed authentication services. Turn off for a strictly evidence-only graph."
        >
          <input
            type="checkbox"
            checked={includeInferred}
            onChange={(e) => setIncludeInferred(e.target.checked)}
          />
          Include inferred steps
        </label>
      </div>

      {data.chokepoints.length > 0 && (
        <div
          style={{
            border: "1px solid var(--border)",
            borderRadius: 4,
            padding: "10px 12px",
            background: "var(--bg-2)",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 7 }}>
            <ShieldAlert size={13} style={{ color: "var(--sev-high)" }} />
            <span style={{ fontSize: 12, fontWeight: 600 }}>Chokepoints</span>
            <span style={{ fontSize: 11, color: "var(--text-3)" }}>
              — fixing these breaks the most routes
            </span>
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {data.chokepoints.map((c) => {
              const Icon = NODE_ICON[c.kind];
              return (
                <span
                  key={c.node_id}
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 5,
                    fontSize: 11.5,
                    background: "var(--bg-3)",
                    border: "1px solid var(--border)",
                    borderRadius: 3,
                    padding: "3px 7px",
                  }}
                >
                  <Icon size={11} style={{ color: "var(--text-3)" }} />
                  {c.label}
                  <span style={{ color: "var(--sev-high)", fontFamily: "var(--font-mono)" }}>
                    ×{c.path_count}
                  </span>
                </span>
              );
            })}
          </div>
        </div>
      )}

      {data.paths.length === 0 ? (
        <div
          style={{
            textAlign: "center",
            color: "var(--text-3)",
            padding: "32px 20px",
            fontSize: 12,
            lineHeight: 1.7,
          }}
        >
          <AlertTriangle size={20} style={{ opacity: 0.5, marginBottom: 8 }} />
          <div style={{ fontWeight: 600, color: "var(--text-2)" }}>No complete attack path found</div>
          <div style={{ maxWidth: 460, margin: "6px auto 0" }}>
            Individual findings may still be serious — this view only reports a route
            when every step from the attacker's position to an objective is backed by
            evidence from this scan.
          </div>
          {/* Distinguish "nothing connects" from "nothing proven". Without this,
              a scan whose only route is a hypothesis just reads as empty. */}
          {!includeInferred && (data.inferred_paths_available ?? 0) > 0 && (
            <div style={{ maxWidth: 460, margin: "10px auto 0" }}>
              <strong style={{ color: "var(--text-2)" }}>
                {data.inferred_paths_available} likely route
                {data.inferred_paths_available === 1 ? "" : "s"}
              </strong>{" "}
              {data.inferred_paths_available === 1 ? "appears" : "appear"} if credential
              reuse is assumed — reasoned from the authentication services this scan
              observed, but not demonstrated.
              <div style={{ marginTop: 8 }}>
                <button className="btn btn-ghost btn-sm" onClick={() => setIncludeInferred(true)}>
                  Show likely routes
                </button>
              </div>
            </div>
          )}
          {!includeInferred && data.inferred_paths_available === 0 && (
            <div style={{ maxWidth: 460, margin: "10px auto 0" }}>
              Nothing connects to an objective here, even allowing for credential reuse.
            </div>
          )}
        </div>
      ) : (
        <div>
          {data.paths.map((p, i) => (
            <PathCard key={p.nodes.join(">")} path={p} rank={i + 1} nodesById={nodesById} />
          ))}
        </div>
      )}
    </div>
  );
}
