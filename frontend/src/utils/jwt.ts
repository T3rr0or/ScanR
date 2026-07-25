/**
 * JWT helpers — decode the role claim from the access token WITHOUT
 * verifying the signature. The server always verifies; this is only for
 * showing/hiding UI affordances, never for authorization decisions.
 */
export function parseJwtRole(token: string | null | undefined): string {
	if (!token) return "analyst";
	try {
		const payload = JSON.parse(atob(token.split(".")[1]));
		return payload.role ?? "analyst";
	} catch {
		return "analyst";
	}
}

export function isAdminToken(token: string | null | undefined): boolean {
	return parseJwtRole(token) === "admin";
}

/**
 * True for read-only ("viewer") accounts. The API rejects writes from viewers
 * with 403 regardless of this — use it only to avoid presenting actions that
 * are guaranteed to fail.
 */
export function isViewerToken(token: string | null | undefined): boolean {
	return parseJwtRole(token) === "viewer";
}
