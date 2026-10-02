import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import QRCode from "qrcode";
import { usersApi } from "@/api/users";
import { apiErrorMessage } from "@/utils/apiError";

const titleStyle = { fontSize: 13, fontWeight: 600, color: "var(--text-0)", marginBottom: 12 };
const noteStyle = { fontSize: 12, color: "var(--text-2)", marginBottom: 12 };
const errorStyle = { color: "var(--sev-high)", fontSize: 12, marginBottom: 8 };

function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
	const text = codes.join("\n");
	const download = () => {
		const url = URL.createObjectURL(new Blob([`ScanR recovery codes\n\n${text}\n`], { type: "text/plain" }));
		const a = document.createElement("a");
		a.href = url;
		a.download = "scanr-recovery-codes.txt";
		a.click();
		URL.revokeObjectURL(url);
	};
	return (
		<div>
			<div style={noteStyle}>
				Save these recovery codes somewhere safe. Each one signs you in once if you lose your
				authenticator. They are shown only now.
			</div>
			<pre className="mono" style={{ fontSize: 13, columns: 2, background: "var(--bg-2)", padding: 12, marginBottom: 12 }}>{text}</pre>
			<div style={{ display: "flex", gap: 8 }}>
				<button className="btn btn-sm" onClick={() => navigator.clipboard.writeText(text)}>Copy</button>
				<button className="btn btn-sm" onClick={download}>Download</button>
				<button className="btn btn-primary btn-sm" onClick={onDone}>I've saved them</button>
			</div>
		</div>
	);
}

export default function TwoFactorPanel() {
	const qc = useQueryClient();
	const { data: status } = useQuery({ queryKey: ["mfa"], queryFn: usersApi.mfaStatus });
	const [password, setPassword] = useState("");
	const [code, setCode] = useState("");
	const [setup, setSetup] = useState<{ secret: string; otpauth_uri: string } | null>(null);
	const [qr, setQr] = useState<string | null>(null);
	const [recovery, setRecovery] = useState<string[] | null>(null);
	const [mode, setMode] = useState<"idle" | "disable" | "regenerate">("idle");
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		if (!setup) return;
		QRCode.toDataURL(setup.otpauth_uri, { margin: 1, width: 180 }).then(setQr).catch(() => setQr(null));
	}, [setup]);

	const reset = () => {
		setPassword("");
		setCode("");
		setError(null);
		setMode("idle");
		qc.invalidateQueries({ queryKey: ["mfa"] });
		qc.invalidateQueries({ queryKey: ["me"] });
	};

	const setupMut = useMutation({
		mutationFn: () => usersApi.mfaSetup(password),
		onSuccess: (data) => {
			setSetup(data);
			setPassword("");
			setError(null);
		},
		onError: (e: unknown) => setError(apiErrorMessage(e)),
	});
	const enableMut = useMutation({
		mutationFn: () => usersApi.mfaEnable(code),
		onSuccess: (data) => {
			setSetup(null);
			setQr(null);
			setRecovery(data.recovery_codes);
			reset();
		},
		onError: (e: unknown) => setError(apiErrorMessage(e)),
	});
	const disableMut = useMutation({
		mutationFn: () => usersApi.mfaDisable(password, code),
		onSuccess: reset,
		onError: (e: unknown) => setError(apiErrorMessage(e)),
	});
	const regenerateMut = useMutation({
		mutationFn: () => usersApi.mfaRegenerateRecoveryCodes(code),
		onSuccess: (data) => {
			setRecovery(data.recovery_codes);
			reset();
		},
		onError: (e: unknown) => setError(apiErrorMessage(e)),
	});

	if (recovery) {
		return (
			<div className="panel" style={{ padding: 16 }}>
				<div style={titleStyle}>Two-factor authentication</div>
				<RecoveryCodes codes={recovery} onDone={() => setRecovery(null)} />
			</div>
		);
	}

	return (
		<div className="panel" style={{ padding: 16 }}>
			<div style={titleStyle}>Two-factor authentication</div>
			{error && <div style={errorStyle}>{error}</div>}

			{status?.enabled ? (
				<>
					<div style={noteStyle}>
						<strong style={{ color: "var(--ok)" }}>On.</strong> Signing in asks for a code from your
						authenticator app. {status.recovery_codes_remaining} recovery code
						{status.recovery_codes_remaining === 1 ? "" : "s"} left.
					</div>
					{mode === "idle" ? (
						<div style={{ display: "flex", gap: 8 }}>
							<button className="btn btn-sm" onClick={() => setMode("regenerate")}>New recovery codes</button>
							<button className="btn btn-sm" onClick={() => setMode("disable")}>Turn off</button>
						</div>
					) : (
						<div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
							{mode === "disable" && (
								<input className="input" type="password" placeholder="Current password" value={password} onChange={(e) => setPassword(e.target.value)} style={{ flex: 1, minWidth: 180 }} />
							)}
							<input className="input" placeholder="Authenticator or recovery code" value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" style={{ flex: 1, minWidth: 200 }} />
							<button
								className="btn btn-primary btn-sm"
								disabled={code.length < 6 || (mode === "disable" && !password) || disableMut.isPending || regenerateMut.isPending}
								onClick={() => (mode === "disable" ? disableMut.mutate() : regenerateMut.mutate())}
							>
								{mode === "disable" ? "Turn off" : "Generate"}
							</button>
							<button className="btn btn-sm" onClick={() => { setMode("idle"); setError(null); }}>Cancel</button>
						</div>
					)}
				</>
			) : setup ? (
				<>
					<div style={noteStyle}>
						Scan this QR code with an authenticator app (Microsoft Authenticator, Google Authenticator,
						1Password, …), then enter the 6-digit code it shows.
					</div>
					<div style={{ display: "flex", gap: 16, alignItems: "flex-start", flexWrap: "wrap", marginBottom: 12 }}>
						{qr && <img src={qr} alt="Authenticator QR code" width={180} height={180} style={{ background: "#fff" }} />}
						<div style={{ fontSize: 12, color: "var(--text-2)" }}>
							Can't scan it? Enter this key manually:
							<div className="mono" style={{ fontSize: 13, color: "var(--text-0)", marginTop: 6, wordBreak: "break-all" }}>
								{setup.secret.match(/.{1,4}/g)?.join(" ")}
							</div>
						</div>
					</div>
					<div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
						<input className="input" placeholder="6-digit code" value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" style={{ flex: 1, minWidth: 140, maxWidth: 200 }} />
						<button className="btn btn-primary btn-sm" disabled={code.length < 6 || enableMut.isPending} onClick={() => enableMut.mutate()}>
							{enableMut.isPending ? "Checking…" : "Turn on"}
						</button>
						<button className="btn btn-sm" onClick={() => { setSetup(null); setQr(null); setCode(""); setError(null); }}>Cancel</button>
					</div>
				</>
			) : (
				<>
					<div style={noteStyle}>
						Off. Add a second step to sign-in so a stolen password is not enough to reach your scans and
						findings. Confirm your password to start.
					</div>
					<div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
						<input className="input" type="password" placeholder="Current password" value={password} onChange={(e) => setPassword(e.target.value)} style={{ flex: 1, minWidth: 180, maxWidth: 320 }} />
						<button className="btn btn-primary btn-sm" disabled={!password || setupMut.isPending} onClick={() => setupMut.mutate()}>
							{setupMut.isPending ? "Starting…" : "Set up"}
						</button>
					</div>
				</>
			)}
		</div>
	);
}
