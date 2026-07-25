/**
 * URL scheme allowlist for links rendered from scan data.
 *
 * Finding `references`, screenshot URLs and similar values originate outside the
 * UI — plugin output, Nuclei templates, NVD feeds, AI-created findings. Putting
 * one straight into `href` would make a `javascript:` (or `data:`) value a
 * one-click script execution in the analyst's session. React escapes text but
 * does NOT sanitise URL schemes in attributes.
 *
 * `react-markdown` already applies an equivalent transform to links inside
 * rendered markdown; this covers the places we build an <a> ourselves.
 */
const SAFE_SCHEMES = new Set(["http:", "https:", "mailto:"]);

/**
 * Returns the URL if its scheme is safe to put in an href, otherwise undefined
 * (so the attribute is omitted and the element is not clickable).
 */
export function safeUrl(raw: string | null | undefined): string | undefined {
	if (!raw) return undefined;
	const trimmed = raw.trim();
	if (!trimmed) return undefined;
	try {
		// Resolve against the current origin so protocol-relative and relative
		// values are handled the same way the browser would.
		const parsed = new URL(trimmed, window.location.origin);
		return SAFE_SCHEMES.has(parsed.protocol) ? trimmed : undefined;
	} catch {
		return undefined;
	}
}

/** True when the value is safe to render as a link. */
export function isSafeUrl(raw: string | null | undefined): boolean {
	return safeUrl(raw) !== undefined;
}
