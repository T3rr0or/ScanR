/**
 * AssistPanel — read-only AI analysis for a scan.
 * Summarize findings, test for false positives, and display saved results.
 * Sits on the right side of the AI tab, next to the AgentPanel.
 */
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import api from "@/api/client";
import type { Finding } from "@/api/findings";

interface SavedResult {
	id: string;
	type: string;
	content: { text?: string; items?: FpItem[]; methodology?: string };
	provider: string;
	model: string;
	token_usage: { input_tokens: number; output_tokens: number } | null;
	created_at: string;
}

interface FpItem {
	id: string;
	confidence: string;
	reason: string;
	verification?: string;
}

interface FpData {
	items: FpItem[];
	methodology?: string;
	assessed_count: number;
	flagged_count: number;
	truncated?: boolean;
	provider: string;
	model: string;
	usage?: { input_tokens: number; output_tokens: number } | null;
}

export default function AssistPanel({
	scanId,
	findings,
	enabled,
}: {
	scanId: string;
	findings: Finding[];
	enabled: boolean;
}) {
	const qc = useQueryClient();

	const { data: savedResults = [] } = useQuery<SavedResult[]>({
		queryKey: ["ai-results", scanId],
		queryFn: () => api.get(`/ai/scans/${scanId}/results`).then((r) => r.data),
		enabled: true,
	});

	const summaryMut = useMutation({
		mutationFn: () =>
			api.post(`/ai/scans/${scanId}/summary`).then((r) => r.data),
		onSuccess: () => qc.invalidateQueries({ queryKey: ["ai-results", scanId] }),
	});

	const fpMut = useMutation({
		mutationFn: () =>
			api.post(`/ai/scans/${scanId}/false-positives`).then((r) => r.data),
		onSuccess: () => qc.invalidateQueries({ queryKey: ["ai-results", scanId] }),
	});

	const pending = summaryMut.isPending || fpMut.isPending;

	const errOf = (m: { error: unknown }): string | null => {
		const e = m.error as {
			response?: { data?: { detail?: string } };
			message?: string;
		} | null;
		if (!e) return null;
		return e.response?.data?.detail ?? e.message ?? "Request failed";
	};

	const findingTitle = (id: string) =>
		findings.find((f) => f.id === id)?.title ?? id;

	const hasFreshSummary = !!summaryMut.data;
	const hasFreshFp = !!fpMut.data;

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
			<div className="panel-head">
				<span className="panel-title">Analysis</span>
				{enabled && (
					<span className="pill pill-completed" style={{ marginLeft: "auto" }}>
						AI ready
					</span>
				)}
				{!enabled && (
					<span className="pill pill-cancelled" style={{ marginLeft: "auto" }}>
						Not configured
					</span>
				)}
			</div>

			<div
				style={{
					padding: 14,
					display: "flex",
					flexDirection: "column",
					gap: 14,
					overflow: "auto",
					flex: 1,
					minHeight: 0,
				}}
			>
				{/* Status message */}
				{!enabled && (
					<div
						style={{
							padding: "10px 12px",
							borderRadius: 6,
							background: "var(--bg-2)",
							border: "1px solid var(--border)",
							fontSize: 12,
							color: "var(--text-2)",
							lineHeight: 1.5,
						}}
					>
						No AI provider configured. Add an API key in{" "}
						<strong>Settings → AI</strong> to enable summaries and
						false-positive testing.
					</div>
				)}

				{/* Actions */}
				<div>
					<div className="panel-title" style={{ marginBottom: 8 }}>
						Read-only actions
					</div>
					<div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
						<button
							className="btn btn-primary btn-sm"
							disabled={!enabled || pending}
							onClick={() => summaryMut.mutate()}
						>
							{summaryMut.isPending ? "Summarizing…" : "Summarize findings"}
						</button>
						<button
							className="btn btn-ghost btn-sm"
							disabled={!enabled || pending}
							onClick={() => fpMut.mutate()}
						>
							{fpMut.isPending ? "Testing…" : "Test false positives"}
						</button>
					</div>
				</div>

				{/* Errors */}
				{[summaryMut, fpMut].map((m, i) => {
					const err = errOf(m);
					return err ? (
						<div key={i} style={{ color: "var(--sev-high)", fontSize: 12 }}>
							{err}
						</div>
					) : null;
				})}

				{/* Fresh + saved summaries */}
				{summaryMut.data && (
					<ResultCard
						title="Summary"
						meta={{
							provider: summaryMut.data.provider,
							model: summaryMut.data.model,
							usage: summaryMut.data.usage,
						}}
						text={summaryMut.data.summary}
						truncated={summaryMut.data.truncated}
					/>
				)}
				{!hasFreshSummary &&
					savedResults
						.filter((r) => r.type === "summary")
						.slice(0, 1)
						.map((r) => (
							<ResultCard
								key={r.id}
								title={`Summary (saved ${new Date(r.created_at).toLocaleString()})`}
								meta={{
									provider: r.provider,
									model: r.model,
									usage: r.token_usage ?? undefined,
								}}
								text={r.content.text ?? ""}
							/>
						))}

				{/* Fresh + saved FP results */}
				{fpMut.data && (
					<FalsePositivePanel
						data={{
							items: fpMut.data.items ?? [],
							methodology: fpMut.data.methodology ?? "",
							assessed_count:
								fpMut.data.assessed_count ?? fpMut.data.items?.length ?? 0,
							flagged_count:
								fpMut.data.flagged_count ?? fpMut.data.items?.length ?? 0,
							truncated: fpMut.data.truncated,
							provider: fpMut.data.provider,
							model: fpMut.data.model,
							usage: fpMut.data.usage,
						}}
						findingTitle={findingTitle}
					/>
				)}
				{!hasFreshFp &&
					savedResults
						.filter((r) => r.type === "false_positives")
						.slice(0, 1)
						.map((r) => (
							<FalsePositivePanel
								key={r.id}
								data={{
									items: r.content.items ?? [],
									methodology: r.content.methodology ?? "",
									assessed_count: r.content.items?.length ?? 0,
									flagged_count: r.content.items?.length ?? 0,
									provider: r.provider,
									model: r.model,
									usage: r.token_usage,
								}}
								findingTitle={findingTitle}
								savedDate={new Date(r.created_at).toLocaleString()}
							/>
						))}

				{!hasFreshSummary &&
					!hasFreshFp &&
					savedResults.length === 0 &&
					!pending && (
						<div
							style={{
								fontSize: 12,
								color: "var(--text-3)",
								textAlign: "center",
								padding: "16px 0",
							}}
						>
							Run an action above to see results here.
						</div>
					)}
			</div>
		</div>
	);
}

/* ── ResultCard (summary display) ───────────── */
function ResultCard({
	title,
	text,
	meta,
	truncated,
}: {
	title: string;
	text: string;
	meta: {
		provider: string;
		model: string;
		usage?: { input_tokens: number; output_tokens: number };
	};
	truncated?: boolean;
}) {
	return (
		<div
			style={{
				border: "1px solid var(--border)",
				borderRadius: 8,
				overflow: "hidden",
				background: "var(--bg-1)",
			}}
		>
			<div
				style={{
					padding: "8px 12px",
					borderBottom: "1px solid var(--border)",
					display: "flex",
					justifyContent: "space-between",
					alignItems: "center",
				}}
			>
				<span style={{ fontSize: 12, fontWeight: 600, color: "var(--text-1)" }}>
					{title}
				</span>
				<span style={{ fontSize: 10.5, color: "var(--text-3)" }}>
					{meta.provider} · {meta.model}
					{meta.usage
						? ` · ${meta.usage.input_tokens + meta.usage.output_tokens} tok`
						: ""}
				</span>
			</div>
			<div
				style={{
					padding: 12,
					whiteSpace: "pre-wrap",
					fontSize: 12.5,
					lineHeight: 1.6,
					color: "var(--text-1)",
				}}
			>
				{truncated && (
					<div
						style={{ fontSize: 11, color: "var(--sev-high)", marginBottom: 8 }}
					>
						⚠ Response truncated (too many findings) — results may be
						incomplete.
					</div>
				)}
				{text}
			</div>
		</div>
	);
}

/* ── FalsePositivePanel ─────────────────────── */
function FalsePositivePanel({
	data,
	findingTitle,
	savedDate,
}: {
	data: FpData & {
		provider: string;
		model: string;
		usage?: { input_tokens: number; output_tokens: number } | null;
	};
	findingTitle: (id: string) => string;
	savedDate?: string;
}) {
	return (
		<div
			style={{
				border: "1px solid var(--border)",
				borderRadius: 8,
				overflow: "hidden",
				background: "var(--bg-1)",
			}}
		>
			<div
				style={{
					padding: "8px 12px",
					borderBottom: "1px solid var(--border)",
					display: "flex",
					justifyContent: "space-between",
					alignItems: "center",
				}}
			>
				<span style={{ fontSize: 12, fontWeight: 600, color: "var(--text-1)" }}>
					{savedDate
						? `False Positive Test (saved ${savedDate})`
						: "Likely false positives"}{" "}
					— {data.flagged_count} of {data.assessed_count}
				</span>
				<span style={{ fontSize: 10.5, color: "var(--text-3)" }}>
					{data.provider} · {data.model}
					{data.usage
						? ` · ${data.usage.input_tokens + data.usage.output_tokens} tok`
						: ""}
				</span>
			</div>
			<div style={{ padding: 12 }}>
				{data.truncated && (
					<div
						style={{ fontSize: 11, color: "var(--sev-high)", marginBottom: 8 }}
					>
						⚠ Response truncated — results may be incomplete.
					</div>
				)}
				{data.methodology && (
					<div
						style={{
							marginBottom: 12,
							padding: "8px 12px",
							background: "var(--bg-0)",
							borderRadius: 6,
							border: "1px solid var(--border)",
							borderLeft: "3px solid var(--accent)",
						}}
					>
						<div
							style={{
								fontSize: 10,
								fontWeight: 600,
								color: "var(--text-3)",
								marginBottom: 6,
								textTransform: "uppercase",
								letterSpacing: "0.05em",
							}}
						>
							Assessment Methodology
						</div>
						<div
							style={{ fontSize: 12, color: "var(--text-1)", lineHeight: 1.55 }}
						>
							{data.methodology}
						</div>
					</div>
				)}

				{data.items.length === 0 ? (
					<div style={{ fontSize: 12, color: "var(--text-2)" }}>
						No findings flagged as likely false positives.
					</div>
				) : (
					<div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
						{data.items.map((it) => (
							<div
								key={it.id}
								style={{
									padding: "8px 10px",
									background: "var(--bg-0)",
									borderRadius: 6,
									border: "1px solid var(--border)",
								}}
							>
								<div
									style={{
										display: "flex",
										alignItems: "center",
										gap: 8,
										marginBottom: 6,
									}}
								>
									<span
										style={{
											fontWeight: 600,
											fontSize: 12,
											color: "var(--text-0)",
											flex: 1,
											overflow: "hidden",
											textOverflow: "ellipsis",
											whiteSpace: "nowrap",
										}}
									>
										{findingTitle(it.id)}
									</span>
									<span
										className={`pill ${it.confidence === "high" ? "pill-cancelled" : it.confidence === "medium" ? "pill-pending" : "pill"}`}
									>
										{it.confidence}
									</span>
								</div>
								<div
									style={{
										fontSize: 11.5,
										color: "var(--text-2)",
										marginBottom: it.verification ? 8 : 0,
									}}
								>
									{it.reason}
								</div>
								{it.verification && (
									<div
										style={{
											padding: "6px 8px",
											background: "var(--bg-1)",
											borderRadius: 4,
											border: "1px solid var(--border)",
										}}
									>
										<div
											style={{
												fontSize: 10,
												fontWeight: 600,
												color: "var(--text-3)",
												marginBottom: 4,
												textTransform: "uppercase",
												letterSpacing: "0.05em",
											}}
										>
											Verification Steps
										</div>
										<pre
											style={{
												margin: 0,
												fontSize: 10.5,
												color: "var(--text-1)",
												whiteSpace: "pre-wrap",
												fontFamily: "var(--font-mono)",
												lineHeight: 1.5,
											}}
										>
											{it.verification}
										</pre>
									</div>
								)}
							</div>
						))}
					</div>
				)}
				<div style={{ fontSize: 10.5, color: "var(--text-3)", marginTop: 10 }}>
					Advisory only — review before marking anything as a false positive.
				</div>
			</div>
		</div>
	);
}
