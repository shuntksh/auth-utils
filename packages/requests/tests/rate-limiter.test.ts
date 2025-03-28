import { afterEach, describe, expect, it, setSystemTime } from "bun:test";

import { LRUCache } from "@auth-utils/requests/lru";
import { RateLimiter } from "@auth-utils/requests/rate-limiter";
import type { RequestEntry } from "@auth-utils/requests/types";

describe("RateLimiter", () => {
	// Reset system time after each test
	afterEach(() => {
		setSystemTime();
	});

	it("should initialize with default options", () => {
		const limiter = new RateLimiter();
		expect(limiter).toBeDefined();
	});

	it("should register and retrieve global policies", () => {
		const limiter = new RateLimiter();

		// Register a policy
		limiter.registerPolicy("api", { windowMs: 60000, maxRequests: 100 });

		// Get all policies
		const policies = limiter.getPolicies();
		expect(policies.api).toBeDefined();
		expect(policies.api.windowMs).toBe(60000);
		expect(policies.api.maxRequests).toBe(100);
	});

	it("should allow requests within rate limit using policy ID", async () => {
		const limiter = new RateLimiter();

		// Register a policy
		limiter.registerPolicy("api", { windowMs: 60000, maxRequests: 5 });

		// Check rate limit using policy ID
		const result1 = await limiter.check("user123", "api");
		expect(result1.success).toBe(true);
		expect(result1.remaining).toBe(4);

		// Make more requests
		const result2 = await limiter.check("user123", "api");
		expect(result2.success).toBe(true);
		expect(result2.remaining).toBe(3);
	});

	it("should block requests that exceed rate limit", async () => {
		const limiter = new RateLimiter();

		// Register a strict policy
		limiter.registerPolicy("strict", { windowMs: 60000, maxRequests: 2 });

		// Make allowed requests
		await limiter.check("user456", "strict");
		await limiter.check("user456", "strict");

		// This should be blocked
		const result = await limiter.check("user456", "strict");
		expect(result.success).toBe(false);
		expect(result.remaining).toBe(0);
	});

	it("should track violations when enabled", async () => {
		const limiter = new RateLimiter({ trackViolations: true });

		// Register a strict policy
		limiter.registerPolicy("strict", { windowMs: 60000, maxRequests: 1 });

		// Make allowed request
		await limiter.check("violator", "strict");

		// Make violating requests
		await limiter.check("violator", "strict");
		await limiter.check("violator", "strict");

		// Check violation count
		expect(limiter.getViolationCount("violator")).toBe(2);

		// Check top violators
		const topViolators = limiter.getTopViolators();
		expect(topViolators.length).toBeGreaterThan(0);
		expect(topViolators[0].uid).toBe("violator");
		expect(topViolators[0].count).toBe(2);
	});

	it("should respect the sliding window", async () => {
		// Mock the current time
		const now = new Date("2023-01-01T12:00:00Z");
		setSystemTime(now);

		const limiter = new RateLimiter();
		limiter.registerPolicy("window", { windowMs: 60000, maxRequests: 2 });

		// Make initial requests at 12:00
		await limiter.check("user789", "window");
		await limiter.check("user789", "window");

		// This should be blocked at 12:00
		let result = await limiter.check("user789", "window");
		expect(result.success).toBe(false);

		// Move time forward by 61 seconds (just outside the window)
		const later = new Date(now.getTime() + 61000);
		setSystemTime(later);

		// This should now be allowed as we're in a new window
		result = await limiter.check("user789", "window");
		expect(result.success).toBe(true);
	});

	it("should clean up expired entries", async () => {
		// Mock the current time
		const now = new Date("2023-01-01T12:00:00Z");
		setSystemTime(now);

		const limiter = new RateLimiter();

		// Register a policy with a short window
		const windowMs = 5000; // 5 seconds
		limiter.registerPolicy("short", { windowMs, maxRequests: 5 });

		// Make a request
		await limiter.check("cleanup-test", "short");

		// Move time forward beyond the window
		const later = new Date(now.getTime() + windowMs + 1000);
		setSystemTime(later);

		// Clean up the expired entries
		await limiter.cleanup("cleanup-test", windowMs);

		// The next request should have full quota again
		const result = await limiter.check("cleanup-test", "short");
		expect(result.success).toBe(true);
		expect(result.remaining).toBe(4); // 5 - 1 = 4
	});

	it("should initialize with custom storage", async () => {
		const customStorage = new LRUCache<RequestEntry[]>(100, {
			ttl: 60000,
			ttlAutoPurge: true,
		});

		const limiter = new RateLimiter({
			storage: customStorage,
			defaultPolicies: {
				default: { windowMs: 60000, maxRequests: 100 },
				api: { windowMs: 30000, maxRequests: 50 },
			},
			cleanupInterval: 60000,
			trackViolations: true,
		});

		// Test with default policy
		const result = await limiter.check("custom-storage", "default");
		expect(result.success).toBe(true);
	});
});
