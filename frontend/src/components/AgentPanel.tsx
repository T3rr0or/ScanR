/**
 * AgentPanel — AI agent chat interface for the scan AI tab.
 * Extracted from ScanDetail.tsx so the tab layout stays clean.
 */
import { useState, useRef, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import api from "@/api/client";
import { useAuthStore } from "@/store/auth";
import { isAdminToken } from "@/utils/jwt";
import { StatusPill } from "@/components/ui";
import Markdown from "@/components/Markdown";

/* ── Types ──────────────────────────────────── */
export interface AgentRun {
	id: string;
	scan_id: string;
	status: string;
	mode: string;
	objective: string;
	provider?: string | null;
	model?: string | null;
	stop_reason?: string | null;
	final_text?: string | null;
	actions: {
		tool: string;
		arguments: Record<string, unknown>;
		result: string;
	}[];
	max_iterations?: number | null;
	max_tokens?: number | null;
	token_usage?: { input_tokens: number; output_tokens: number } | null;
	error?: string | null;
	pending_approval?: {
		approval_id: string;
		tool: string;
		args: Record<string, unknown>;
		reason: string;
	} | null;
	conversation?: {
		role: string;
		content?: string;
		tool_calls?: {
			id: string;
			name: string;
			arguments: Record<string, unknown>;
		}[];
		tool_call_id?: string;
		name?: string;
	}[];
	created_at?: string | null;
}

/* ── Capability presets ─────────────────────── */
const CAPS: Record<
	string,
	{
		aggressive: boolean;
		allow_exploitation: boolean;
		allow_privilege_escalation: boolean;
		allow_command_exec: boolean;
	}
> = {
	analyze: {
		aggressive: false,
		allow_exploitation: false,
		allow_privilege_escalation: false,
		allow_command_exec: false,
	},
	active: {
		aggressive: true,
		allow_exploitation: false,
		allow_privilege_escalation: false,
		allow_command_exec: false,
	},
	full: {
		aggressive: true,
		allow_exploitation: true,
		allow_privilege_escalation: true,
		allow_command_exec: true,
	},
};

const CAP_LABEL: Record<string, string> = {
	analyze: "Read-only",
	active: "Active",
	full: "Full",
};

const PROVIDER_LABEL: Record<string, string> = {
	anthropic: "Claude",
	openai: "ChatGPT",
	deepseek: "DeepSeek",
};

const SETTINGS_KEY = "scanr_agent_settings";

function loadSettings(): {
	mode: "guided" | "autonomous";
	capability: "analyze" | "active" | "full";
	maxIterations: number;
	maxTokens: number;
	provider: string;
} {
	try {
		const raw = localStorage.getItem(SETTINGS_KEY);
		if (raw) return { provider: "", ...JSON.parse(raw) };
	} catch {
		/* ignore */
	}
	return {
		mode: "guided",
		capability: "analyze",
		maxIterations: 25,
		maxTokens: 200000,
		provider: "",
	};
}

function saveSettings(s: {
	mode: string;
	capability: string;
	maxIterations: number;
	maxTokens: number;
	provider: string;
}) {
	try {
		localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
	} catch {
		/* ignore */
	}
}

/* ── Main component ─────────────────────────── */
export default function AgentPanel({
	scanId,
	enabled,
}: {
	scanId: string;
	enabled: boolean;
}) {
	const qc = useQueryClient();
	const token = useAuthStore((s) => s.token);
	const isAdmin = isAdminToken(token);

	const [saved] = useState(loadSettings);
	const [message, setMessage] = useState("");
	const [mode, setMode] = useState<"guided" | "autonomous">(saved.mode);
	const [maxIterations, setMaxIterations] = useState(saved.maxIterations);
	const [maxTokens, setMaxTokens] = useState(saved.maxTokens);
	const [capability, setCapability] = useState<"analyze" | "active" | "full">(
		saved.capability,
	);
	const [provider, setProvider] = useState(saved.provider);
	const [showSettings, setShowSettings] = useState(false);

	// Configured providers, for the model switcher (provider with a key set).
	const { data: aiStatus } = useQuery<{
		providers: string[];
		configured: Record<string, boolean>;
		default_provider: string;
	}>({
		queryKey: ["ai-status"],
		queryFn: () => api.get("/ai/status").then((r) => r.data),
	});
	const availableProviders = (aiStatus?.providers ?? []).filter(
		(p) => aiStatus?.configured?.[p],
	);
	const [forceNew, setForceNew] = useState(false);
	const [sending, setSending] = useState(false);
	const chatRef = useRef<HTMLDivElement>(null);

	// Persist settings whenever they change.
	useEffect(() => {
		saveSettings({ mode, capability, maxIterations, maxTokens, provider });
	}, [mode, capability, maxIterations, maxTokens, provider]);

	const { data: runs = [] } = useQuery<AgentRun[]>({
		queryKey: ["ai-agent-runs", scanId],
		queryFn: () =>
			api.get(`/ai/scans/${scanId}/agent/runs`).then((r) => r.data),
		refetchInterval: (q) =>
			(q.state.data ?? []).some((r) => ["queued", "running"].includes(r.status))
				? 4000
				: false,
	});

	const launch = useMutation({
		mutationFn: (msg: string) => {
			const c = CAPS[capability];
			return api
				.post(`/ai/scans/${scanId}/agent`, {
					mode,
					objective: msg.trim(),
					max_iterations: maxIterations,
					max_tokens: maxTokens,
					provider: provider || undefined,
					aggressive: isAdmin && c.aggressive,
					allow_exploitation: isAdmin && c.allow_exploitation,
					allow_privilege_escalation: isAdmin && c.allow_privilege_escalation,
					allow_command_exec: isAdmin && c.allow_command_exec,
				})
				.then((r) => r.data);
		},
		onSuccess: () => {
			setMessage("");
			qc.invalidateQueries({ queryKey: ["ai-agent-runs", scanId] });
		},
		onSettled: () => setSending(false),
	});

	const chatMut = useMutation({
		mutationFn: ({ runId, msg }: { runId: string; msg: string }) =>
			api
				.post(`/ai/agent/runs/${runId}/chat`, {
					message: msg,
					provider: provider || undefined,
				})
				.then((r) => r.data),
		onSuccess: () => {
			setMessage("");
			qc.invalidateQueries({ queryKey: ["ai-agent-runs", scanId] });
		},
		onSettled: () => setSending(false),
	});

	const stopMut = useMutation({
		mutationFn: (runId: string) =>
			api.post(`/ai/agent/runs/${runId}/stop`).then((r) => r.data),
		onSuccess: () =>
			qc.invalidateQueries({ queryKey: ["ai-agent-runs", scanId] }),
	});

	const launchErr = (() => {
		const e = (launch.error ?? chatMut.error) as {
			response?: { data?: { detail?: string } };
		} | null;
		return e?.response?.data?.detail ?? null;
	})();

	const active = runs.some((r) => ["queued", "running"].includes(r.status));
	const latestRun = runs[0];
	const canChat =
		latestRun?.status === "completed" && latestRun?.conversation?.length;

	const send = () => {
		const msg = message.trim();
		if (
			!msg ||
			!enabled ||
			launch.isPending ||
			chatMut.isPending ||
			active ||
			sending
		)
			return;
		setSending(true);
		if (canChat && latestRun && !forceNew) {
			chatMut.mutate({ runId: latestRun.id, msg });
		} else {
			setForceNew(false);
			launch.mutate(msg);
		}
	};

	useEffect(() => {
		if (chatRef.current)
			chatRef.current.scrollTop = chatRef.current.scrollHeight;
	}, [runs]);

	const exportTrace = async (runId: string) => {
		const resp = await api.get(`/ai/agent/runs/${runId}/export`, {
			params: { format: "md" },
			responseType: "blob",
		});
		const url = URL.createObjectURL(resp.data as Blob);
		const a = document.createElement("a");
		a.href = url;
		a.download = `agent-trace-${runId.slice(0, 8)}.md`;
		document.body.appendChild(a);
		a.click();
		a.remove();
		URL.revokeObjectURL(url);
	};

	// Map tool results back to the calls that produced them
	const toolResults: Record<string, string> = {};
	for (const m of latestRun?.conversation ?? []) {
		if (m.role === "tool" && m.tool_call_id)
			toolResults[m.tool_call_id] = m.content ?? "";
	}

	return (
		<div
			className="panel"
			style={{
				display: "flex",
				flexDirection: "column",
				flex: 1,
				minHeight: 0,
			}}
		>
			{/* Header with settings summary */}
			<div className="panel-head" style={{ justifyContent: "space-between" }}>
				<span className="panel-title">AI Agent</span>
				<div style={{ display: "flex", gap: 6, alignItems: "center" }}>
					{!!latestRun?.conversation?.length && (
						<button
							className="btn btn-ghost btn-sm"
							onClick={() => exportTrace(latestRun.id)}
							title="Download the full agent trace (every command + result) for audit / cleanup"
							style={{ fontSize: 11 }}
						>
							⬇ Export
						</button>
					)}
					{canChat && (
						<button
							className="btn btn-primary btn-sm"
							onClick={() => {
								setForceNew(true);
							}}
							title="Start a new run with current settings"
							style={{ fontSize: 11 }}
						>
							<Plus size={11} /> New
						</button>
					)}
					<button
						className="btn btn-ghost btn-sm"
						onClick={() => setShowSettings((s) => !s)}
						style={{ fontSize: 11 }}
					>
						{provider ? `${PROVIDER_LABEL[provider] ?? provider} · ` : ""}
						{mode} · {CAP_LABEL[capability]} ·{" "}
						{maxIterations === 0 ? "∞" : maxIterations} steps ·{" "}
						{maxTokens === 0 ? "∞" : `${Math.round(maxTokens / 1000)}k`} tok{" "}
						{showSettings ? "▲" : "▼"}
					</button>
				</div>
			</div>

			{/* Collapsible settings */}
			{showSettings && (
				<div
					style={{
						padding: "10px 14px",
						borderBottom: "1px solid var(--border)",
						display: "flex",
						flexDirection: "column",
						gap: 8,
					}}
				>
					<div style={{ display: "flex", gap: 8 }}>
						{(["guided", "autonomous"] as const).map((m) => (
							<button
								key={m}
								className={`btn btn-sm ${mode === m ? "btn-primary" : "btn-ghost"}`}
								onClick={() => setMode(m)}
								style={{ flex: 1, fontSize: 11.5 }}
							>
								{m === "guided" ? "🛡 Guided (you approve)" : "🚀 Autonomous"}
							</button>
						))}
					</div>
					{availableProviders.length > 0 && (
						<div style={{ display: "flex", alignItems: "center", gap: 8 }}>
							<span style={{ fontSize: 11, color: "var(--text-3)" }}>
								Model:
							</span>
							<select
								className="input"
								value={provider}
								onChange={(e) => setProvider(e.target.value)}
								style={{ fontSize: 11.5, flex: 1 }}
								title="Switch the AI model — applies to the next message, including mid-conversation"
							>
								<option value="">
									Default
									{aiStatus?.default_provider
										? ` (${PROVIDER_LABEL[aiStatus.default_provider] ?? aiStatus.default_provider})`
										: ""}
								</option>
								{availableProviders.map((p) => (
									<option key={p} value={p}>
										{PROVIDER_LABEL[p] ?? p}
									</option>
								))}
							</select>
						</div>
					)}
					<div
						style={{
							display: "flex",
							alignItems: "center",
							gap: 8,
							flexWrap: "wrap",
						}}
					>
						<span style={{ fontSize: 11, color: "var(--text-3)" }}>
							Max steps:
						</span>
						<input
							type="number"
							className="input"
							min={1}
							max={200}
							value={maxIterations === 0 ? "" : maxIterations}
							disabled={maxIterations === 0}
							placeholder="∞"
							onChange={(e) =>
								setMaxIterations(
									Math.max(1, Math.min(200, Number(e.target.value) || 1)),
								)
							}
							style={{ width: 48, fontSize: 11.5 }}
						/>
						<button
							type="button"
							className={`btn btn-sm ${maxIterations === 0 ? "btn-primary" : "btn-ghost"}`}
							onClick={() => setMaxIterations((v) => (v === 0 ? 25 : 0))}
							style={{ fontSize: 12, padding: "2px 8px" }}
							title="No step limit"
						>
							∞
						</button>
						<span style={{ fontSize: 11, color: "var(--text-3)" }}>
							Max tokens:
						</span>
						<input
							type="number"
							className="input"
							min={1}
							step={10}
							value={maxTokens === 0 ? "" : Math.round(maxTokens / 1000)}
							disabled={maxTokens === 0}
							placeholder="∞"
							onChange={(e) =>
								setMaxTokens(
									Math.max(
										1000,
										Math.min(2000000, (Number(e.target.value) || 1) * 1000),
									),
								)
							}
							style={{ width: 48, fontSize: 11.5 }}
							title="Token safety cap (thousands)"
						/>
						<span style={{ fontSize: 11, color: "var(--text-3)" }}>k</span>
						<button
							type="button"
							className={`btn btn-sm ${maxTokens === 0 ? "btn-primary" : "btn-ghost"}`}
							onClick={() => setMaxTokens((v) => (v === 0 ? 200000 : 0))}
							style={{ fontSize: 12, padding: "2px 8px" }}
							title="No token limit"
						>
							∞
						</button>
					</div>
					{isAdmin && (
						<div style={{ display: "flex", gap: 6 }}>
							{(["analyze", "active", "full"] as const).map((c) => (
								<button
									key={c}
									className={`btn btn-sm ${capability === c ? "btn-primary" : "btn-ghost"}`}
									onClick={() => setCapability(c)}
									style={{ flex: 1, fontSize: 11 }}
								>
									{c === "analyze"
										? "📋 Read-only"
										: c === "active"
											? "🔍 Active"
											: "💣 Full"}
								</button>
							))}
						</div>
					)}
				</div>
			)}

			{/* Chat messages */}
			<div
				ref={chatRef}
				style={{
					flex: 1,
					overflowY: "auto",
					padding: "10px 14px",
					display: "flex",
					flexDirection: "column",
					gap: 8,
				}}
			>
				{!latestRun && !active && !forceNew && (
					<div
						style={{
							fontSize: 12,
							color: "var(--text-3)",
							textAlign: "center",
							padding: 20,
						}}
					>
						Send a message to start the agent.
					</div>
				)}

				{!forceNew &&
					latestRun?.conversation?.map((msg, i) => {
						if (msg.role === "user") {
							return (
								<div
									key={i}
									style={{ display: "flex", justifyContent: "flex-end" }}
								>
									<div
										style={{
											maxWidth: "80%",
											padding: "8px 12px",
											borderRadius: 12,
											borderBottomRightRadius: 4,
											background: "var(--accent)",
											color: "#fff",
											fontSize: 13,
											lineHeight: 1.5,
										}}
									>
										{msg.content}
									</div>
								</div>
							);
						}
						if (msg.role === "assistant") {
							const hasTools = msg.tool_calls && msg.tool_calls.length > 0;
							return (
								<div
									key={i}
									style={{ display: "flex", flexDirection: "column", gap: 4 }}
								>
									{msg.content && (
										<div
											style={{
												maxWidth: "85%",
												padding: "8px 12px",
												borderRadius: 12,
												borderBottomLeftRadius: 4,
												background: "var(--bg-2)",
												border: "1px solid var(--border)",
											}}
										>
											<Markdown>{msg.content}</Markdown>
										</div>
									)}
									{hasTools && (
										<ToolCallsBlock
											calls={msg.tool_calls!}
											results={toolResults}
										/>
									)}
								</div>
							);
						}
						return null;
					})}

				{/* Thinking indicator */}
				{(launch.isPending ||
					chatMut.isPending ||
					(active && latestRun?.status !== "completed")) && (
					<div
						style={{
							display: "flex",
							gap: 8,
							alignItems: "center",
							padding: "8px 12px",
						}}
					>
						<div
							style={{
								width: 8,
								height: 8,
								borderRadius: "50%",
								background: "var(--accent)",
								animation: "pulse-dot 1s infinite",
							}}
						/>
						<span style={{ fontSize: 12, color: "var(--text-3)" }}>
							Agent is thinking…
						</span>
						<span style={{ flex: 1 }} />
						{latestRun && active && (
							<button
								className="btn btn-ghost btn-sm"
								onClick={() => stopMut.mutate(latestRun.id)}
								disabled={stopMut.isPending}
								style={{ fontSize: 11, color: "var(--sev-high)" }}
								title="Stop the agent after its current step"
							>
								{stopMut.isPending ? "Stopping…" : "⏹ Stop"}
							</button>
						)}
					</div>
				)}

				{/* Approval prompt */}
				{latestRun?.pending_approval && (
					<ApprovalCard run={latestRun} scanId={scanId} />
				)}

				{/* Legacy run cards (non-chat runs) */}
				{runs
					.filter((r) => !r.conversation?.length)
					.map((run) => (
						<AgentRunCard key={run.id} run={run} scanId={scanId} />
					))}

				{launchErr && (
					<div
						style={{
							color: "var(--sev-high)",
							fontSize: 11.5,
							textAlign: "center",
						}}
					>
						{launchErr}
					</div>
				)}
				{!enabled && (
					<div
						style={{
							fontSize: 11,
							color: "var(--text-3)",
							textAlign: "center",
						}}
					>
						Configure a provider key in Settings → AI first.
					</div>
				)}
			</div>

			{/* Input */}
			<div
				style={{
					padding: "8px 14px",
					borderTop: "1px solid var(--border)",
					display: "flex",
					gap: 8,
				}}
			>
				<input
					className="input"
					placeholder={
						canChat
							? "Continue the conversation…"
							: "What should the agent investigate?"
					}
					value={message}
					onChange={(e) => setMessage(e.target.value)}
					onKeyDown={(e) => {
						if (e.key === "Enter" && !e.shiftKey) {
							e.preventDefault();
							send();
						}
					}}
					disabled={!enabled || launch.isPending || chatMut.isPending || active}
					style={{ flex: 1, fontSize: 13 }}
				/>
				<button
					className="btn btn-primary btn-sm"
					disabled={
						!enabled ||
						!message.trim() ||
						launch.isPending ||
						chatMut.isPending ||
						active
					}
					onClick={send}
				>
					▶
				</button>
			</div>
		</div>
	);
}

/* ── ToolCallsBlock ─────────────────────────── */
function ToolCallsBlock({
	calls,
	results,
}: {
	calls: { id: string; name: string; arguments: Record<string, unknown> }[];
	results: Record<string, string>;
}) {
	const [open, setOpen] = useState(false);
	return (
		<div style={{ marginLeft: 8 }}>
			<button
				onClick={() => setOpen((o) => !o)}
				className="btn btn-ghost btn-sm"
				style={{
					fontSize: 11,
					color: "var(--text-3)",
					fontFamily: "var(--font-mono)",
					padding: "2px 6px",
				}}
			>
				{open ? "▾" : "▸"} {calls.length} tool call
				{calls.length !== 1 ? "s" : ""}
			</button>
			{open && (
				<div
					style={{
						display: "flex",
						flexDirection: "column",
						gap: 4,
						marginTop: 4,
					}}
				>
					{calls.map((tc, j) => (
						<div
							key={j}
							style={{ display: "flex", flexDirection: "column", gap: 2 }}
						>
							<div
								style={{
									padding: "3px 8px",
									borderRadius: 6,
									background: "var(--bg-2)",
									border: "1px solid var(--border)",
									fontSize: 11,
									fontFamily: "var(--font-mono)",
									color: "var(--accent)",
									wordBreak: "break-all",
								}}
							>
								🔧 {tc.name}({JSON.stringify(tc.arguments)})
							</div>
							{results[tc.id] !== undefined && (
								<div
									style={{
										marginLeft: 8,
										padding: "3px 8px",
										borderRadius: 6,
										background: "var(--bg-1)",
										border: "1px solid var(--border)",
										fontSize: 10.5,
										fontFamily: "var(--font-mono)",
										color: "var(--text-3)",
										maxHeight: 160,
										overflowY: "auto",
										whiteSpace: "pre-wrap",
									}}
								>
									{results[tc.id].slice(0, 2000)}
								</div>
							)}
						</div>
					))}
				</div>
			)}
		</div>
	);
}

/* ── ApprovalCard ───────────────────────────── */
function ApprovalCard({ run, scanId }: { run: AgentRun; scanId: string }) {
	const qc = useQueryClient();
	const decide = useMutation({
		mutationFn: (decision: "allow" | "deny") =>
			api.post(`/ai/agent/runs/${run.id}/approval`, {
				approval_id: run.pending_approval?.approval_id,
				decision,
			}),
		onSuccess: () =>
			qc.invalidateQueries({ queryKey: ["ai-agent-runs", scanId] }),
	});
	return (
		<div
			style={{
				padding: 10,
				borderRadius: 6,
				background: "var(--bg-2)",
				border: "2px solid var(--sev-medium)",
			}}
		>
			<div
				style={{
					fontSize: 12.5,
					fontWeight: 700,
					color: "var(--sev-medium)",
					marginBottom: 4,
				}}
			>
				⏸ Agent paused — needs your approval
			</div>
			<div
				style={{
					fontSize: 11.5,
					fontFamily: "var(--font-mono)",
					color: "var(--text-2)",
				}}
			>
				{run.pending_approval?.tool}(
				{JSON.stringify(run.pending_approval?.args)})
			</div>
			<div style={{ display: "flex", gap: 8, marginTop: 8 }}>
				<button
					className="btn btn-primary btn-sm"
					disabled={decide.isPending}
					onClick={() => decide.mutate("allow")}
				>
					✓ Approve
				</button>
				<button
					className="btn btn-sm"
					disabled={decide.isPending}
					onClick={() => decide.mutate("deny")}
					style={{ color: "var(--sev-high)", borderColor: "var(--sev-high)" }}
				>
					✗ Deny
				</button>
			</div>
		</div>
	);
}

/* ── AgentRunCard (legacy, non-chat runs) ───── */
function AgentRunCard({ run, scanId }: { run: AgentRun; scanId: string }) {
	const running = ["queued", "running"].includes(run.status);
	const [open, setOpen] = useState(running);
	const qc = useQueryClient();

	const stopLabel: Record<string, string> = {
		end: "Agent finished",
		budget: "Reached token limit",
		max_iterations: "Reached step limit",
		stopped: "Stopped by you",
		error: "Error",
	};

	const decide = useMutation({
		mutationFn: (decision: "allow" | "deny") =>
			api.post(`/ai/agent/runs/${run.id}/approval`, {
				approval_id: run.pending_approval?.approval_id,
				decision,
			}),
		onSuccess: () =>
			qc.invalidateQueries({ queryKey: ["ai-agent-runs", scanId] }),
	});

	return (
		<div
			style={{
				border: "1px solid var(--border)",
				borderRadius: 8,
				padding: "10px 12px",
			}}
		>
			<div
				style={{
					display: "flex",
					alignItems: "center",
					gap: 8,
					flexWrap: "wrap",
				}}
			>
				<StatusPill status={run.status} />
				<span style={{ fontSize: 11, color: "var(--text-3)" }}>{run.mode}</span>
				{run.provider && (
					<span style={{ fontSize: 11, color: "var(--text-3)" }}>
						{run.provider}/{run.model}
					</span>
				)}
				{run.token_usage && (
					<span style={{ fontSize: 11, color: "var(--text-3)" }}>
						{run.token_usage.input_tokens + run.token_usage.output_tokens} tok
					</span>
				)}
				{run.stop_reason && run.status === "completed" && (
					<span style={{ fontSize: 10.5, color: "var(--text-3)" }}>
						· {stopLabel[run.stop_reason] ?? run.stop_reason}
					</span>
				)}
				<span style={{ flex: 1 }} />
				{run.actions.length > 0 && (
					<button
						className="btn btn-ghost btn-sm"
						onClick={() => setOpen((o) => !o)}
					>
						{open
							? "Hide steps"
							: `${run.actions.length} step${run.actions.length !== 1 ? "s" : ""}`}
					</button>
				)}
			</div>
			{run.objective && (
				<div style={{ fontSize: 11.5, color: "var(--text-2)", marginTop: 4 }}>
					{run.objective}
				</div>
			)}

			{run.pending_approval && (
				<div
					style={{
						marginTop: 8,
						padding: 10,
						borderRadius: 6,
						background: "var(--bg-2)",
						border: "2px solid var(--sev-medium)",
					}}
				>
					<div
						style={{
							fontSize: 12.5,
							fontWeight: 700,
							color: "var(--sev-medium)",
							marginBottom: 4,
						}}
					>
						⏸ Agent paused — needs your approval
					</div>
					<div
						style={{
							fontSize: 11.5,
							fontFamily: "var(--font-mono)",
							color: "var(--text-2)",
						}}
					>
						{run.pending_approval.tool}(
						{JSON.stringify(run.pending_approval.args)})
					</div>
					<div style={{ display: "flex", gap: 8, marginTop: 8 }}>
						<button
							className="btn btn-primary btn-sm"
							disabled={decide.isPending}
							onClick={() => decide.mutate("allow")}
						>
							✓ Approve
						</button>
						<button
							className="btn btn-sm"
							disabled={decide.isPending}
							onClick={() => decide.mutate("deny")}
							style={{
								color: "var(--sev-high)",
								borderColor: "var(--sev-high)",
							}}
						>
							✗ Deny
						</button>
					</div>
				</div>
			)}

			{run.error && (
				<div
					style={{
						color: "var(--sev-high)",
						fontSize: 12,
						marginTop: 6,
						padding: 8,
						background: "var(--bg-2)",
						borderRadius: 4,
					}}
				>
					{run.error}
				</div>
			)}

			{run.final_text && (
				<div style={{ marginTop: 10 }}>
					<div
						style={{
							fontSize: 11,
							fontWeight: 600,
							color: "var(--text-2)",
							marginBottom: 4,
						}}
					>
						📝 Agent report
					</div>
					<Markdown>{run.final_text}</Markdown>
				</div>
			)}

			{run.status === "completed" && !run.final_text && !run.error && (
				<div
					style={{
						fontSize: 11.5,
						color: "var(--text-3)",
						marginTop: 6,
						fontStyle: "italic",
					}}
				>
					Agent stopped without producing a report. Expand steps to see what
					happened.
				</div>
			)}

			{open && run.actions.length > 0 && (
				<div
					style={{
						marginTop: 8,
						display: "flex",
						flexDirection: "column",
						gap: 6,
						maxHeight: 400,
						overflowY: "auto",
					}}
				>
					{run.actions.map((a, i) => (
						<div
							key={i}
							style={{
								fontSize: 11.5,
								fontFamily: "var(--font-mono)",
								color: "var(--text-2)",
							}}
						>
							<div style={{ color: "var(--accent)", fontWeight: 600 }}>
								→ {a.tool}({JSON.stringify(a.arguments)})
							</div>
							<div style={{ whiteSpace: "pre-wrap", color: "var(--text-3)" }}>
								{a.result.slice(0, 1200)}
							</div>
						</div>
					))}
				</div>
			)}
		</div>
	);
}
