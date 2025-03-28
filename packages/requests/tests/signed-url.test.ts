import { afterEach, describe, expect, it, setSystemTime } from "bun:test";

import {
	SignedUrlParamError,
	createSignedUrl,
	parseSignedUrlParams,
	verifySignedUrl,
} from "@auth-utils/requests/signed-url";

describe("Signed URL", () => {
	const testKey = "test-access-key";
	const testSecret = "test-secret-key";
	const testUrl = "https://example.com/resource/123";

	// Reset system time after each test
	afterEach(() => {
		setSystemTime();
	});

	describe("parseSignedUrlParams", () => {
		it("should parse valid parameters", () => {
			const params = new URLSearchParams();
			params.set("X-Key", "test-key");
			params.set("X-Expires", "1672531200");
			params.set("X-Signature", "test-signature");
			params.set("custom", "value");

			const result = parseSignedUrlParams(params);

			expect(result["X-Key"]).toBe("test-key");
			expect(result["X-Expires"]).toBe("1672531200");
			expect(result["X-Signature"]).toBe("test-signature");
			expect(result.custom).toBe("value");
		});

		it("should throw error for missing X-Key", () => {
			const params = new URLSearchParams();
			params.set("X-Expires", "1672531200");

			expect(() => parseSignedUrlParams(params)).toThrow(SignedUrlParamError);
			expect(() => parseSignedUrlParams(params)).toThrow(
				"Missing required parameter: X-Key",
			);
		});

		it("should throw error for missing X-Expires", () => {
			const params = new URLSearchParams();
			params.set("X-Key", "test-key");

			expect(() => parseSignedUrlParams(params)).toThrow(SignedUrlParamError);
			expect(() => parseSignedUrlParams(params)).toThrow(
				"Missing required parameter: X-Expires",
			);
		});

		it("should throw error for invalid X-Expires format", () => {
			const params = new URLSearchParams();
			params.set("X-Key", "test-key");
			params.set("X-Expires", "not-a-number");

			expect(() => parseSignedUrlParams(params)).toThrow(SignedUrlParamError);
			expect(() => parseSignedUrlParams(params)).toThrow(
				"X-Expires must be a numeric timestamp",
			);
		});
	});

	describe("createSignedUrl", () => {
		it("should create a signed URL with default expiration", async () => {
			// Mock the current time
			const mockTime = new Date("2023-01-01T00:00:00Z");
			setSystemTime(mockTime);

			const params = await createSignedUrl(testUrl, testKey, testSecret);

			// Check required parameters
			expect(params.has("X-Key")).toBe(true);
			expect(params.get("X-Key")).toBe(testKey);
			expect(params.has("X-Expires")).toBe(true);
			expect(params.has("X-Signature")).toBe(true);

			// Check hostname and path are included
			expect(params.has("X-Hostname")).toBe(true);
			expect(params.get("X-Hostname")).toBe("example.com");
			expect(params.has("X-Path")).toBe(true);
			expect(params.get("X-Path")).toBe("/resource/123");

			// Verify expiration time (15 minutes from mock time)
			const expectedExpires = Math.floor(mockTime.getTime() / 1000) + 15 * 60;
			expect(params.get("X-Expires")).toBe(expectedExpires.toString());
		});

		it("should create a signed URL with custom expiration", async () => {
			// Mock the current time
			const mockTime = new Date("2023-01-01T00:00:00Z");
			setSystemTime(mockTime);

			const customExpiration = 3600; // 1 hour
			const params = await createSignedUrl(testUrl, testKey, testSecret, {
				expiresIn: customExpiration,
			});

			// Verify expiration time (1 hour from mock time)
			const expectedExpires =
				Math.floor(mockTime.getTime() / 1000) + customExpiration;
			expect(params.get("X-Expires")).toBe(expectedExpires.toString());
		});

		it("should throw error for negative expiration time", async () => {
			await expect(
				createSignedUrl(testUrl, testKey, testSecret, {
					expiresIn: -60,
				}),
			).rejects.toThrow("Expiration time must be positive");
		});

		it("should throw error for expiration time exceeding maximum", async () => {
			const maxExpiresIn = 3600; // 1 hour max

			await expect(
				createSignedUrl(testUrl, testKey, testSecret, {
					expiresIn: 7200, // 2 hours
					maxExpiresIn,
				}),
			).rejects.toThrow(
				`Expiration time exceeds maximum allowed (${maxExpiresIn} seconds)`,
			);
		});

		it("should include nonce when provided", async () => {
			const nonce = "unique-nonce-123";
			const params = await createSignedUrl(testUrl, testKey, testSecret, {
				nonce,
			});

			expect(params.has("X-Nonce")).toBe(true);
			expect(params.get("X-Nonce")).toBe(nonce);
		});

		it("should include additional query parameters", async () => {
			const additionalParams = {
				action: "download",
				version: "1.0",
			};

			const params = await createSignedUrl(testUrl, testKey, testSecret, {
				queryParams: additionalParams,
			});

			// Check additional parameters
			expect(params.get("action")).toBe("download");
			expect(params.get("version")).toBe("1.0");
		});

		it("should throw error when trying to override reserved parameters", async () => {
			const additionalParams = {
				"X-Key": "override-attempt",
			};

			await expect(
				createSignedUrl(testUrl, testKey, testSecret, {
					queryParams: additionalParams,
				}),
			).rejects.toThrow("Cannot override reserved parameter: X-Key");
		});

		it("should throw error when trying to override X-Hostname parameter", async () => {
			const additionalParams = {
				"X-Hostname": "override-attempt",
			};

			await expect(
				createSignedUrl(testUrl, testKey, testSecret, {
					queryParams: additionalParams,
				}),
			).rejects.toThrow("Cannot override reserved parameter: X-Hostname");
		});

		it("should throw error when trying to override X-Nonce parameter", async () => {
			const additionalParams = {
				"X-Nonce": "override-attempt",
			};

			await expect(
				createSignedUrl(testUrl, testKey, testSecret, {
					queryParams: {
						"X-Nonce": "override-attempt",
					},
				}),
			).rejects.toThrow("Cannot override reserved parameter: X-Nonce");
		});
	});

	describe("verifySignedUrl", () => {
		it("should verify a valid signed URL (URL object)", async () => {
			// Mock the current time
			const mockTime = new Date("2023-01-01T00:00:00Z");
			setSystemTime(mockTime);

			// Create a signed URL
			const params = await createSignedUrl(testUrl, testKey, testSecret);

			// Create a URL with the signed parameters
			const signedUrl = new URL(testUrl);
			for (const [key, value] of params.entries()) {
				signedUrl.searchParams.set(key, value);
			}

			// Verify the signed URL
			const result = await verifySignedUrl(signedUrl, testKey, testSecret);
			expect(result.valid).toBe(true);
			expect(result.reason).toBeUndefined();
		});

		it("should verify a valid signed URL (string)", async () => {
			// Mock the current time
			const mockTime = new Date("2023-01-01T00:00:00Z");
			setSystemTime(mockTime);

			// Create a signed URL
			const params = await createSignedUrl(testUrl, testKey, testSecret);

			// Create a URL string with the signed parameters
			const signedUrl = new URL(testUrl);
			for (const [key, value] of params.entries()) {
				signedUrl.searchParams.set(key, value);
			}

			// Verify the signed URL as a string
			const result = await verifySignedUrl(
				signedUrl.toString(),
				testKey,
				testSecret,
			);
			expect(result.valid).toBe(true);
			expect(result.reason).toBeUndefined();
		});

		it("should verify a valid signed URL (URLSearchParams)", async () => {
			// Mock the current time
			const mockTime = new Date("2023-01-01T00:00:00Z");
			setSystemTime(mockTime);

			// Create a signed URL
			const params = await createSignedUrl(testUrl, testKey, testSecret);

			// Create a new URLSearchParams to avoid modifying the original
			const verificationParams = new URLSearchParams();

			// Copy all parameters from the signed URL
			for (const [key, value] of params.entries()) {
				verificationParams.set(key, value);
			}

			// Verify the signed URL as URLSearchParams
			const result = await verifySignedUrl(
				verificationParams,
				testKey,
				testSecret,
			);

			expect(result.valid).toBe(true);
			expect(result.reason).toBeUndefined();
		});

		it("should verify a valid signed URL with nonce", async () => {
			// Mock the current time
			const mockTime = new Date("2023-01-01T00:00:00Z");
			setSystemTime(mockTime);

			const nonce = "unique-nonce-123";

			// Create a signed URL with nonce
			const params = await createSignedUrl(testUrl, testKey, testSecret, {
				nonce,
			});

			// Create a URL with the signed parameters
			const signedUrl = new URL(testUrl);
			for (const [key, value] of params.entries()) {
				signedUrl.searchParams.set(key, value);
			}

			// Verify the signed URL with the same nonce
			const result = await verifySignedUrl(signedUrl, testKey, testSecret, {
				nonce,
			});
			expect(result.valid).toBe(true);
			expect(result.reason).toBeUndefined();
		});

		it("should reject a URL with invalid nonce", async () => {
			// Mock the current time
			const mockTime = new Date("2023-01-01T00:00:00Z");
			setSystemTime(mockTime);

			const nonce = "unique-nonce-123";

			// Create a signed URL with nonce
			const params = await createSignedUrl(testUrl, testKey, testSecret, {
				nonce,
			});

			// Create a URL with the signed parameters
			const signedUrl = new URL(testUrl);
			for (const [key, value] of params.entries()) {
				signedUrl.searchParams.set(key, value);
			}

			// Verify with different nonce
			const result = await verifySignedUrl(signedUrl, testKey, testSecret, {
				nonce: "different-nonce",
			});
			expect(result.valid).toBe(false);
			expect(result.reason).toBe("Invalid nonce");
		});

		it("should reject an expired URL", async () => {
			// Mock the current time for creation
			const creationTime = new Date("2023-01-01T00:00:00Z");
			setSystemTime(creationTime);

			// Create a signed URL with 10 second expiration
			const params = await createSignedUrl(testUrl, testKey, testSecret, {
				expiresIn: 10,
			});

			// Create a URL with the signed parameters
			const signedUrl = new URL(testUrl);
			for (const [key, value] of params.entries()) {
				signedUrl.searchParams.set(key, value);
			}

			// Move time forward past expiration
			const verificationTime = new Date("2023-01-01T00:00:20Z"); // 20 seconds later
			setSystemTime(verificationTime);

			// Verify the signed URL
			const result = await verifySignedUrl(signedUrl, testKey, testSecret);
			expect(result.valid).toBe(false);
			expect(result.reason).toBe("URL has expired");
		});

		it("should reject a URL with invalid key", async () => {
			// Create a signed URL
			const params = await createSignedUrl(testUrl, testKey, testSecret);

			// Create a URL with the signed parameters
			const signedUrl = new URL(testUrl);
			for (const [key, value] of params.entries()) {
				signedUrl.searchParams.set(key, value);
			}

			// Verify with wrong key
			const wrongKey = "wrong-access-key";
			const result = await verifySignedUrl(signedUrl, wrongKey, testSecret);
			expect(result.valid).toBe(false);
			expect(result.reason).toBe("Invalid key");
		});

		it("should reject a URL with tampered signature", async () => {
			// Create a signed URL
			const params = await createSignedUrl(testUrl, testKey, testSecret);

			// Create a URL with the signed parameters
			const signedUrl = new URL(testUrl);
			for (const [key, value] of params.entries()) {
				signedUrl.searchParams.set(key, value);
			}

			// Tamper with the signature
			signedUrl.searchParams.set("X-Signature", "tampered-signature");

			// Verify the signed URL
			const result = await verifySignedUrl(signedUrl, testKey, testSecret);
			expect(result.valid).toBe(false);
			expect(result.reason).toBe("Invalid signature");
		});

		it("should reject a URL with missing parameters", async () => {
			// Create a URL without required parameters
			const invalidUrl = new URL(testUrl);

			// Verify the URL
			const result = await verifySignedUrl(invalidUrl, testKey, testSecret);
			expect(result.valid).toBe(false);
			expect(result.reason).toBe("Missing required parameter: X-Key");
		});

		it("should reject URLSearchParams without hostname/path", async () => {
			// Create params without hostname and path
			const params = new URLSearchParams();
			params.set("X-Key", testKey);
			params.set("X-Expires", "1672531200"); // 2023-01-01T00:00:00Z
			params.set("X-Signature", "some-signature");

			// Verify the params
			const result = await verifySignedUrl(params, testKey, testSecret);
			expect(result.valid).toBe(false);
			expect(result.reason).toBe(
				"Missing hostname or path information in URLSearchParams",
			);
		});

		it("should log verification failures when logger is provided", async () => {
			// Create a mock logger
			const loggedEvents: Array<{
				valid: boolean;
				reason?: string;
				context: Record<string, unknown>;
			}> = [];

			const mockLogger = (info: {
				valid: boolean;
				reason?: string;
				context: Record<string, unknown>;
			}) => {
				loggedEvents.push(info);
			};

			// Create a URL without required parameters
			const invalidUrl = new URL(testUrl);

			// Verify the URL with logger
			await verifySignedUrl(invalidUrl, testKey, testSecret, {
				logger: mockLogger,
			});

			// Check that the logger was called
			expect(loggedEvents.length).toBe(1);
			expect(loggedEvents[0].valid).toBe(false);
			expect(loggedEvents[0].reason).toBe("Missing required parameter: X-Key");
			expect(loggedEvents[0].context.urlType).toBe("URL");
		});
	});
});
