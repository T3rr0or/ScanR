import { describe, expect, it } from "vitest";

import { apiErrorMessage } from "./apiError";

describe("apiErrorMessage", () => {
	it("uses a string detail from HTTPException", () => {
		const err = { response: { data: { detail: "Current password is incorrect" } } };
		expect(apiErrorMessage(err)).toBe("Current password is incorrect");
	});

	it("unpacks a 422 validation array instead of rendering [object Object]", () => {
		// The shape FastAPI returns when a password exceeds bcrypt's byte limit.
		const err = {
			response: {
				data: {
					detail: [
						{
							type: "value_error",
							loc: ["body", "new_password"],
							msg: "Value error, password must be at most 72 bytes when UTF-8 encoded",
						},
					],
				},
			},
		};
		expect(apiErrorMessage(err)).toContain("72 bytes");
		expect(apiErrorMessage(err)).not.toContain("object Object");
	});

	it("joins multiple validation errors", () => {
		const err = { response: { data: { detail: [{ msg: "too short" }, { msg: "too long" }] } } };
		expect(apiErrorMessage(err)).toBe("too short; too long");
	});

	it("falls back to the Error message when there is no response body", () => {
		expect(apiErrorMessage(new Error("Network Error"))).toBe("Network Error");
	});

	it("never returns an empty string", () => {
		expect(apiErrorMessage({})).toBe("Failed");
		expect(apiErrorMessage(null)).toBe("Failed");
		// Entries with no usable `msg` must not collapse to "".
		expect(apiErrorMessage({ response: { data: { detail: [{}] } } })).toBe("Failed");
		// An empty string detail is not a usable message either.
		expect(apiErrorMessage({ response: { data: { detail: "" } } })).toBe("Failed");
		expect(apiErrorMessage(new Error(""))).toBe("Failed");
	});

	it("honours a custom fallback", () => {
		expect(apiErrorMessage({}, "Could not save")).toBe("Could not save");
	});
});
