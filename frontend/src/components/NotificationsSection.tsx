import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Send, Trash2 } from "lucide-react";
import { notificationsApi, type ChannelKind, type NotificationEvent } from "@/api/notifications";
import { relTime } from "@/components/ui";
import { apiErrorMessage } from "@/utils/apiError";

const KINDS: { id: ChannelKind; label: string; placeholder: string; help: string }[] = [
	{
		id: "teams",
		label: "Microsoft Teams",
		placeholder: "https://….logic.azure.com/workflows/…",
		help: "In Teams: channel ⋯ → Workflows → \"Post to a channel when a webhook request is received\", then paste the URL it gives you.",
	},
	{
		id: "slack",
		label: "Slack",
		placeholder: "https://hooks.slack.com/services/…",
		help: "Create an incoming webhook for the channel in your Slack app settings and paste its URL.",
	},
	{
		id: "email",
		label: "Email",
		placeholder: "security-team@example.com",
		help: "Sent through the SMTP server configured by your administrator.",
	},
];

const THRESHOLDS: { value: string; label: string }[] = [
	{ value: "", label: "Every finished scan" },
	{ value: "40", label: "Only if something scores 40+ (plan)" },
	{ value: "60", label: "Only if something scores 60+ (fix soon)" },
	{ value: "80", label: "Only if something scores 80+ (fix now)" },
];

const EMPTY = { name: "", kind: "teams" as ChannelKind, target: "", completed: true, failed: true, threshold: "" };

export default function NotificationsSection() {
	const qc = useQueryClient();
	const [form, setForm] = useState(EMPTY);
	const [showCreate, setShowCreate] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const { data: config } = useQuery({ queryKey: ["notifications-config"], queryFn: notificationsApi.config });
	const { data: channels = [] } = useQuery({ queryKey: ["notifications"], queryFn: notificationsApi.list });
	const refresh = () => qc.invalidateQueries({ queryKey: ["notifications"] });
	const onError = (e: unknown) => setError(apiErrorMessage(e));

	const createMut = useMutation({
		mutationFn: () => {
			const events: NotificationEvent[] = [];
			if (form.completed) events.push("scan.completed");
			if (form.failed) events.push("scan.failed");
			return notificationsApi.create({
				name: form.name,
				kind: form.kind,
				target: form.target,
				events,
				min_priority: form.threshold ? Number(form.threshold) : null,
			});
		},
		onSuccess: () => {
			setForm(EMPTY);
			setShowCreate(false);
			setError(null);
			refresh();
		},
		onError,
	});
	const toggleMut = useMutation({
		mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => notificationsApi.update(id, { enabled }),
		onSuccess: refresh,
		onError,
	});
	const deleteMut = useMutation({ mutationFn: notificationsApi.remove, onSuccess: refresh, onError });
	const testMut = useMutation({ mutationFn: notificationsApi.test, onSuccess: refresh, onError });

	const kind = KINDS.find((k) => k.id === form.kind) ?? KINDS[0];
	const emailBlocked = form.kind === "email" && config && !config.email_enabled;

	return (
		<div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
			<div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
				<p style={{ fontSize: 12, color: "var(--text-3)", margin: 0 }}>
					Get a short summary in Teams, Slack or your inbox when one of your scans finishes or fails, with the findings to fix first.
				</p>
				<button className="btn btn-primary btn-sm" onClick={() => setShowCreate((v) => !v)}>
					<Plus size={13} /> New channel
				</button>
			</div>

			{error && <div style={{ color: "var(--sev-high)", fontSize: 12 }}>{error}</div>}

			{showCreate && (
				<div className="panel" style={{ padding: 14, display: "flex", flexDirection: "column", gap: 10 }}>
					<div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
						<select className="select-field" value={form.kind} onChange={(e) => setForm((f) => ({ ...f, kind: e.target.value as ChannelKind, target: "" }))} aria-label="Channel type">
							{KINDS.map((k) => <option key={k.id} value={k.id}>{k.label}</option>)}
						</select>
						<input className="input" placeholder="Name, e.g. SOC channel" value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
					</div>
					<input className="input" placeholder={kind.placeholder} value={form.target} onChange={(e) => setForm((f) => ({ ...f, target: e.target.value }))} aria-label={form.kind === "email" ? "Email address" : "Webhook URL"} />
					<div style={{ fontSize: 11, color: "var(--text-3)" }}>{kind.help}</div>
					{emailBlocked && (
						<div style={{ fontSize: 12, color: "var(--sev-medium)" }}>
							Email is not set up on this server yet. An administrator needs to set SMTP_HOST and SMTP_FROM.
						</div>
					)}
					<div style={{ display: "flex", gap: 16, flexWrap: "wrap", alignItems: "center", fontSize: 12, color: "var(--text-1)" }}>
						<label style={{ display: "flex", gap: 6, alignItems: "center" }}>
							<input type="checkbox" checked={form.completed} onChange={(e) => setForm((f) => ({ ...f, completed: e.target.checked }))} /> Scan finished
						</label>
						<label style={{ display: "flex", gap: 6, alignItems: "center" }}>
							<input type="checkbox" checked={form.failed} onChange={(e) => setForm((f) => ({ ...f, failed: e.target.checked }))} /> Scan failed
						</label>
						<select className="select-field" value={form.threshold} onChange={(e) => setForm((f) => ({ ...f, threshold: e.target.value }))} aria-label="When a finished scan notifies" style={{ minWidth: 260 }} disabled={!form.completed}>
							{THRESHOLDS.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
						</select>
					</div>
					<div style={{ display: "flex", gap: 8 }}>
						<button className="btn btn-primary btn-sm" disabled={!form.name || !form.target || (!form.completed && !form.failed) || !!emailBlocked || createMut.isPending} onClick={() => createMut.mutate()}>
							Create
						</button>
						<button className="btn btn-ghost btn-sm" onClick={() => setShowCreate(false)}>Cancel</button>
					</div>
				</div>
			)}

			<div className="panel" style={{ overflow: "hidden" }}>
				<table className="tbl" style={{ width: "100%" }}>
					<thead>
						<tr>
							<th>Name</th>
							<th>Destination</th>
							<th>When</th>
							<th>Last delivery</th>
							<th></th>
						</tr>
					</thead>
					<tbody>
						{channels.map((c) => (
							<tr key={c.id} style={{ opacity: c.enabled ? 1 : 0.55 }}>
								<td style={{ fontSize: 12 }}>
									<strong>{c.name}</strong>
									<div className="dimmer" style={{ fontSize: 10 }}>{KINDS.find((k) => k.id === c.kind)?.label ?? c.kind}</div>
								</td>
								<td className="mono dimmer" style={{ fontSize: 11 }}>{c.target}</td>
								<td style={{ fontSize: 11, color: "var(--text-2)" }}>
									{c.events.map((e) => (e === "scan.completed" ? "finished" : "failed")).join(", ")}
									{c.min_priority != null && c.events.includes("scan.completed") && <div className="dimmer">priority {c.min_priority}+</div>}
								</td>
								<td style={{ fontSize: 11 }}>
									{c.last_status === "sent" && <span style={{ color: "var(--ok)" }}>Sent {relTime(c.last_sent_at)}</span>}
									{c.last_status === "failed" && <span style={{ color: "var(--sev-high)" }} title={c.last_error ?? ""}>Failed {relTime(c.last_sent_at)}: {c.last_error}</span>}
									{!c.last_status && <span className="dimmer">Never</span>}
								</td>
								<td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
									<button className="btn btn-ghost btn-sm" style={{ fontSize: 11 }} onClick={() => testMut.mutate(c.id)} disabled={testMut.isPending} title="Send an example message now">
										<Send size={12} /> Test
									</button>
									<button className="btn btn-ghost btn-sm" style={{ fontSize: 11 }} onClick={() => toggleMut.mutate({ id: c.id, enabled: !c.enabled })}>
										{c.enabled ? "Pause" : "Resume"}
									</button>
									<button className="btn btn-ghost btn-icon btn-sm" title="Delete" style={{ color: "var(--sev-high)" }} onClick={() => deleteMut.mutate(c.id)}>
										<Trash2 size={13} />
									</button>
								</td>
							</tr>
						))}
						{channels.length === 0 && (
							<tr>
								<td colSpan={5} style={{ padding: "32px 16px", textAlign: "center", color: "var(--text-3)", fontSize: 12 }}>
									No notification channels yet
								</td>
							</tr>
						)}
					</tbody>
				</table>
			</div>
		</div>
	);
}
