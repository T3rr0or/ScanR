/**
 * Token-refresh behaviour of the shared axios client.
 *
 * The interesting case is concurrency: when several requests 401 at once, only
 * the first should refresh and the rest should queue behind it. These drive that
 * through real axios by swapping in a custom adapter, so the interceptor logic
 * runs exactly as it does in the browser.
 */
import axios, { type AxiosAdapter, type AxiosResponse, type InternalAxiosRequestConfig } from "axios";
import { beforeEach, describe, expect, it, vi } from "vitest";

type Reply = { status: number; data?: unknown };

/** Programmed replies per path, consumed in order; the last one repeats. */
function makeAdapter(script: Record<string, Reply[]>) {
	const calls: string[] = [];

	const adapter: AxiosAdapter = (config: InternalAxiosRequestConfig) => {
		const url = config.url ?? "";
		calls.push(url);
		const queue = script[url];
		const reply = queue
			? (queue.length > 1 ? queue.shift()! : queue[0])
			: { status: 200, data: {} };

		const response: AxiosResponse = {
			data: reply.data ?? {},
			status: reply.status,
			statusText: String(reply.status),
			headers: {},
			config,
			request: {},
		};

		if (reply.status >= 200 && reply.status < 300) return Promise.resolve(response);
		return Promise.reject(
			new axios.AxiosError(
				`Request failed with status code ${reply.status}`,
				String(reply.status),
				config,
				{},
				response,
			),
		);
	};

	return { adapter, calls };
}

/** Fresh module state per test — `refreshing`/`refreshQueue` are module-level. */
async function loadClient(adapter: AxiosAdapter) {
	vi.resetModules();
	sessionStorage.clear();
	const { useAuthStore } = await import("@/store/auth");
	useAuthStore.getState().setToken("old-token");

	const mod = await import("@/api/client");
	const api = mod.default;
	api.defaults.adapter = adapter;
	// The refresh call is made on the bare axios instance, not `api`.
	axios.defaults.adapter = adapter;
	return { api, useAuthStore };
}

const REFRESH = "/api/v1/auth/refresh";

describe("api client token refresh", () => {
	beforeEach(() => {
		sessionStorage.clear();
	});

	it("refreshes once and retries the failed request", async () => {
		const { adapter, calls } = makeAdapter({
			"/scans": [{ status: 401 }, { status: 200, data: { ok: true } }],
			[REFRESH]: [{ status: 200, data: { access_token: "new-token" } }],
		});
		const { api, useAuthStore } = await loadClient(adapter);

		const res = await api.get("/scans");

		expect(res.data).toEqual({ ok: true });
		expect(calls.filter((c) => c === REFRESH)).toHaveLength(1);
		expect(useAuthStore.getState().token).toBe("new-token");
	});

	it("collapses concurrent 401s into a single refresh", async () => {
		const { adapter, calls } = makeAdapter({
			"/scans": [{ status: 401 }, { status: 200, data: { n: 1 } }],
			"/findings": [{ status: 401 }, { status: 200, data: { n: 2 } }],
			[REFRESH]: [{ status: 200, data: { access_token: "new-token" } }],
		});
		const { api } = await loadClient(adapter);

		const [a, b] = await Promise.all([api.get("/scans"), api.get("/findings")]);

		expect(a.data).toEqual({ n: 1 });
		expect(b.data).toEqual({ n: 2 });
		expect(calls.filter((c) => c === REFRESH)).toHaveLength(1);
	});

	it("logs out when the refresh itself fails", async () => {
		const { adapter } = makeAdapter({
			"/scans": [{ status: 401 }],
			[REFRESH]: [{ status: 401 }],
		});
		const { api, useAuthStore } = await loadClient(adapter);

		await expect(api.get("/scans")).rejects.toBeTruthy();
		expect(useAuthStore.getState().token).toBeNull();
	});

	/**
	 * The claim under test: a request that queued behind someone else's refresh
	 * is replayed without `_retry` being set, so if it 401s again it starts a
	 * refresh of its own rather than giving up.
	 *
	 * `/scans` drives the first refresh and then succeeds. `/findings` queues
	 * behind it and 401s forever, so only the queued path can produce a second
	 * refresh.
	 */
	it("does not let a queued request start a second refresh round", async () => {
		const { adapter, calls } = makeAdapter({
			"/scans": [{ status: 401 }, { status: 200, data: { n: 1 } }],
			"/findings": [{ status: 401 }],
			[REFRESH]: [{ status: 200, data: { access_token: "new-token" } }],
		});
		const { api } = await loadClient(adapter);

		const results = await Promise.allSettled([api.get("/scans"), api.get("/findings")]);

		expect(results[0].status).toBe("fulfilled");
		expect(results[1].status).toBe("rejected");
		expect(calls.filter((c) => c === REFRESH)).toHaveLength(1);
	});

	it("stays at one refresh no matter how many queued requests keep 401ing", async () => {
		// The cost of the bug scaled with concurrency: every queued request that
		// 401ed again ran its own refresh, so a page issuing several calls at once
		// produced a burst against /auth/refresh.
		const paths = ["/a", "/b", "/c", "/d", "/e"];
		const script: Record<string, Reply[]> = {
			"/scans": [{ status: 401 }, { status: 200, data: { n: 1 } }],
			[REFRESH]: [{ status: 200, data: { access_token: "new-token" } }],
		};
		for (const p of paths) script[p] = [{ status: 401 }];

		const { adapter, calls } = makeAdapter(script);
		const { api } = await loadClient(adapter);

		const results = await Promise.allSettled([
			api.get("/scans"),
			...paths.map((p) => api.get(p)),
		]);

		expect(results[0].status).toBe("fulfilled");
		expect(results.slice(1).every((r) => r.status === "rejected")).toBe(true);
		expect(calls.filter((c) => c === REFRESH)).toHaveLength(1);
	});
});
