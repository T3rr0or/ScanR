/**
 * Readable messages from failed API calls.
 *
 * FastAPI returns two different `detail` shapes and the difference matters:
 * an HTTPException sends a plain string ("Current password is incorrect"),
 * while a 422 from schema validation sends an array of error objects. Rendering
 * the array straight into the DOM prints "[object Object]", hiding the actual
 * reason — which for password fields is where the length limits surface.
 */
export function apiErrorMessage(e: unknown, fallback = "Failed"): string {
	const detail = (e as { response?: { data?: { detail?: unknown } } })?.response?.data
		?.detail;
	if (typeof detail === "string" && detail) return detail;
	if (Array.isArray(detail)) {
		const messages = detail
			.map((d) => (d as { msg?: string })?.msg)
			.filter((m): m is string => typeof m === "string" && m.length > 0);
		if (messages.length) return messages.join("; ");
	}
	return e instanceof Error && e.message ? e.message : fallback;
}
