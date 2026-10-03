import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Download } from "lucide-react";
import { auditApi, type AuditEvent, type AuditFilters } from "@/api/audit";

const PAGE = 100;

const ACTION_GROUPS = [
	{ value: "", label: "All actions" },
	{ value: "auth.", label: "Sign-ins" },
	{ value: "users", label: "Users and 2FA" },
	{ value: "scans", label: "Scans" },
	{ value: "findings", label: "Findings" },
	{ value: "reports", label: "Reports" },
	{ value: "credentials", label: "Credentials" },
	{ value: "api_keys", label: "API keys" },
	{ value: "system", label: "System" },
];

function outcomeColor(status: number | null) {
	if (status == null) return "var(--text-3)";
	if (status >= 400) return "var(--sev-high)";
	return "var(--ok)";
}

function Details({ event }: { event: AuditEvent }) {
	if (!event.details) return null;
	let text = event.details;
	try {
		const parsed = JSON.parse(event.details) as Record<string, unknown>;
		text = Object.entries(parsed).map(([k, v]) => `${k}: ${String(v)}`).join(" · ");
	} catch {
		/* show raw */
	}
	return <div className="dimmer" style={{ fontSize: 10, marginTop: 2 }}>{text}</div>;
}

export default function AuditLogSection() {
	const [filters, setFilters] = useState<AuditFilters>({ user: "", action: "", outcome: "" });
	const [pages, setPages] = useState(1);
	const [exporting, setExporting] = useState(false);
	const query = { ...filters, limit: PAGE * pages + 1 };
	const { data = [], isFetching } = useQuery({
		queryKey: ["audit", query],
		queryFn: () => auditApi.list(query),
		placeholderData: (prev) => prev,
	});
	const more = data.length > PAGE * pages;
	const rows = more ? data.slice(0, PAGE * pages) : data;
	const set = (patch: AuditFilters) => {
		setFilters((f) => ({ ...f, ...patch }));
		setPages(1);
	};

	return (
		<div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
			<p style={{ fontSize: 12, color: "var(--text-3)", margin: 0 }}>
				Every change made through ScanR, every sign-in attempt and every export, with who, when and from which
				address. Entries cannot be edited or deleted. Passwords and other secrets are never recorded.
			</p>
			<div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
				<input className="input" placeholder="User email contains…" value={filters.user} onChange={(e) => set({ user: e.target.value })} style={{ width: "auto", flex: "1 1 220px" }} aria-label="Filter by user" />
				<select className="select-field" value={filters.action} onChange={(e) => set({ action: e.target.value })} aria-label="Filter by action" style={{ width: "auto", flex: "0 1 180px" }}>
					{ACTION_GROUPS.map((g) => <option key={g.value} value={g.value}>{g.label}</option>)}
				</select>
				<select className="select-field" value={filters.outcome} onChange={(e) => set({ outcome: e.target.value as AuditFilters["outcome"] })} aria-label="Filter by outcome" style={{ width: "auto", flex: "0 1 200px" }}>
					<option value="">Allowed and denied</option>
					<option value="allowed">Allowed only</option>
					<option value="denied">Denied or failed only</option>
				</select>
				<button className="btn btn-sm" style={{ flexShrink: 0 }} disabled={exporting} onClick={async () => { setExporting(true); try { await auditApi.exportCsv(filters); } finally { setExporting(false); } }}>
					<Download size={13} /> {exporting ? "Exporting…" : "Export CSV"}
				</button>
			</div>
			<div className="panel" style={{ overflow: "auto" }}>
				<table className="tbl" style={{ width: "100%" }}>
					<thead>
						<tr>
							<th>When</th>
							<th>Who</th>
							<th>Action</th>
							<th>Target</th>
							<th>Result</th>
							<th>From</th>
						</tr>
					</thead>
					<tbody>
						{rows.map((e) => (
							<tr key={e.id}>
								<td className="mono" style={{ fontSize: 11, whiteSpace: "nowrap" }}>{new Date(e.created_at).toLocaleString()}</td>
								<td style={{ fontSize: 12 }}>
									{e.user_email ?? <span className="dimmer">anonymous</span>}
									{e.auth_method === "api_key" && <div className="dimmer" style={{ fontSize: 10 }}>API key</div>}
								</td>
								<td style={{ fontSize: 12 }}>
									<span className="mono">{e.action}</span>
									<Details event={e} />
								</td>
								<td className="mono dimmer" style={{ fontSize: 11 }} title={e.path ?? ""}>{e.target_id ? e.target_id.slice(0, 8) : "–"}</td>
								<td className="mono" style={{ fontSize: 11, color: outcomeColor(e.status_code) }}>
									{e.status_code == null ? "–" : e.status_code >= 400 ? `denied ${e.status_code}` : `ok ${e.status_code}`}
								</td>
								<td className="mono dimmer" style={{ fontSize: 11 }}>{e.ip ?? "–"}</td>
							</tr>
						))}
						{rows.length === 0 && (
							<tr>
								<td colSpan={6} style={{ padding: "32px 16px", textAlign: "center", color: "var(--text-3)", fontSize: 12 }}>
									{isFetching ? "Loading…" : "No matching events"}
								</td>
							</tr>
						)}
					</tbody>
				</table>
			</div>
			{more && (
				<button className="btn btn-sm" style={{ alignSelf: "center" }} onClick={() => setPages((n) => n + 1)} disabled={isFetching}>
					Show older entries
				</button>
			)}
		</div>
	);
}
