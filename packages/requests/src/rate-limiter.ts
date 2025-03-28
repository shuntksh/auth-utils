import { LRUCache } from "./lru";
import type {
	RateLimitPolicy,
	RateLimitResponse,
	RateLimitStorage,
	RequestEntry,
} from "./types";

import { RequestError } from "./deps";

/**
 * Configuration options for the RateLimiter
 */
export interface RateLimiterOptions {
	/**
	 * Default policies to apply when no specific policy is provided
	 */
	defaultPolicies?: Record<string, RateLimitPolicy>;

	/**
	 * Storage adapter for persisting rate limit data
	 */
	storage?: RateLimitStorage;

	/**
	 * Whether to enable token bucket algorithm for smoother rate limiting
	 * This allows for bursts of traffic while maintaining the overall rate limit
	 */
	useTokenBucket?: boolean;

	/**
	 * Interval in ms for automatic cleanup of expired entries (0 to disable)
	 */
	cleanupInterval?: number;

	/**
	 * Whether to track and log rate limit violations
	 */
	trackViolations?: boolean;

	/**
	 * Maximum number of violations to track per client
	 */
	maxViolationsTracked?: number;
}

/**
 * A sliding window rate limiter implementation with enhanced security features.
 * Provides protection against DDoS attacks by implementing configurable rate limiting
 * policies that can be applied globally or per-route.
 */
export class RateLimiter {
	private storage: RateLimitStorage;
	private defaultPolicies: Record<string, RateLimitPolicy> = {};
	private useTokenBucket: boolean;
	private cleanupTimer?: ReturnType<typeof setInterval>;
	private trackViolations: boolean;
	private maxViolationsTracked: number;
	private violationCounts: Map<string, number> = new Map();

	constructor(options: RateLimiterOptions = {}) {
		// Initialize storage adapter
		this.storage = options.storage || new LRUCache<RequestEntry[]>();

		// Validate storage adapter
		if (
			!this.storage ||
			typeof this.storage.get !== "function" ||
			typeof this.storage.set !== "function"
		) {
			throw new RequestError("Invalid storage adapter provided");
		}

		// Initialize configuration options
		this.defaultPolicies = options.defaultPolicies || {};
		this.useTokenBucket = options.useTokenBucket || false;
		this.trackViolations = options.trackViolations || false;
		this.maxViolationsTracked = options.maxViolationsTracked || 1000;

		// Set up automatic cleanup if interval is provided
		if (options.cleanupInterval && options.cleanupInterval > 0) {
			this.cleanupTimer = setInterval(() => {
				this.globalCleanup();
			}, options.cleanupInterval);
		}
	}

	/**
	 * Registers a global policy for a specific identifier (e.g., route, API endpoint)
	 * @param policyId Unique identifier for the policy
	 * @param policy Rate limiting policy to apply
	 */
	registerPolicy(policyId: string, policy: RateLimitPolicy): void {
		if (!policyId || typeof policyId !== "string") {
			throw new RequestError("Invalid policy ID");
		}
		if (!policy || policy.maxRequests <= 0 || policy.windowMs <= 0) {
			throw new RequestError("Invalid rate limit policy");
		}

		this.defaultPolicies[policyId] = policy;
	}

	/**
	 * Removes a global policy
	 * @param policyId Unique identifier for the policy to remove
	 */
	removePolicy(policyId: string): boolean {
		if (this.defaultPolicies[policyId]) {
			delete this.defaultPolicies[policyId];
			return true;
		}
		return false;
	}

	/**
	 * Gets all registered policies
	 */
	getPolicies(): Record<string, RateLimitPolicy> {
		return { ...this.defaultPolicies };
	}

	/**
	 * Checks if a request is allowed under the rate limit policy.
	 * @param uid Unique identifier for the client (e.g., user ID, IP)
	 * @param policyIdOrPolicy Rate limiting policy ID or policy object
	 * @returns RateLimitResponse indicating if the request is allowed
	 */
	async check(
		uid: string,
		policyIdOrPolicy: string | RateLimitPolicy,
	): Promise<RateLimitResponse> {
		// Input validation
		if (!uid || typeof uid !== "string") {
			throw new RequestError("Invalid UID");
		}

		// Determine which policy to use
		let policy: RateLimitPolicy;

		if (typeof policyIdOrPolicy === "string") {
			// Look up policy by ID
			policy = this.defaultPolicies[policyIdOrPolicy];
			if (!policy) {
				throw new RequestError(`Policy not found: ${policyIdOrPolicy}`);
			}
		} else if (
			typeof policyIdOrPolicy === "object" &&
			policyIdOrPolicy.maxRequests > 0 &&
			policyIdOrPolicy.windowMs > 0
		) {
			// Use provided policy object
			policy = policyIdOrPolicy;
		} else {
			throw new RequestError("Invalid policy identifier or object");
		}

		const now = Date.now();
		const windowStart = now - policy.windowMs;

		// Fetch existing requests from storage
		const requests = (await this.storage.get(uid)) ?? [];

		// Filter out requests outside the sliding window
		const filteredRequests = requests.filter(
			(req) => req.timestamp >= windowStart,
		);

		// Calculate total requests in the window
		const totalRequests = filteredRequests.reduce(
			(sum, req) => sum + req.count,
			0,
		);

		// Check if rate limit is exceeded
		if (totalRequests >= policy.maxRequests) {
			// Rate limit exceeded
			const earliestRequest = filteredRequests[0];
			const resetTime = earliestRequest?.timestamp
				? earliestRequest.timestamp + policy.windowMs
				: now + policy.windowMs;

			// Track violation if enabled
			if (this.trackViolations) {
				this.recordViolation(uid);
			}

			return {
				success: false,
				remaining: 0,
				resetTime,
			};
		}

		// Optimize by aggregating requests at the same timestamp
		const lastRequest = filteredRequests[filteredRequests.length - 1];
		if (lastRequest && lastRequest.timestamp === now) {
			lastRequest.count += 1; // Increment count if timestamp matches
		} else {
			filteredRequests.push({ timestamp: now, count: 1 });
		}

		// Persist updated requests
		await this.storage.set(uid, filteredRequests);

		return {
			success: true,
			remaining: policy.maxRequests - (totalRequests + 1),
			resetTime: now + policy.windowMs,
		};
	}

	/**
	 * Records a rate limit violation for tracking and potential blocking
	 * @param uid Unique identifier for the client
	 */
	private recordViolation(uid: string): void {
		const currentCount = this.violationCounts.get(uid) || 0;
		this.violationCounts.set(uid, currentCount + 1);

		// Prune violation tracking if it gets too large
		if (this.violationCounts.size > this.maxViolationsTracked) {
			// Remove the oldest entries (this is a simple approach)
			const entries = Array.from(this.violationCounts.entries());
			entries.sort((a, b) => b[1] - a[1]); // Sort by count descending

			// Keep only the top violations
			this.violationCounts = new Map(
				entries.slice(0, this.maxViolationsTracked),
			);
		}
	}

	/**
	 * Gets the number of violations for a specific client
	 * @param uid Unique identifier for the client
	 */
	getViolationCount(uid: string): number {
		return this.violationCounts.get(uid) || 0;
	}

	/**
	 * Gets clients with the highest violation counts
	 * @param limit Maximum number of clients to return
	 */
	getTopViolators(limit = 10): Array<{ uid: string; count: number }> {
		const entries = Array.from(this.violationCounts.entries());
		entries.sort((a, b) => b[1] - a[1]); // Sort by count descending

		return entries.slice(0, limit).map(([uid, count]) => ({ uid, count }));
	}

	/**
	 * Cleans up expired entries for a given UID.
	 * Useful for periodic maintenance to prevent memory leaks.
	 * @param uid Unique identifier
	 * @param windowMs Window size in milliseconds
	 */
	async cleanup(uid: string, windowMs: number): Promise<void> {
		const windowStart = Date.now() - windowMs;
		const requests = (await this.storage.get(uid)) ?? [];
		const filteredRequests = requests.filter(
			(req) => req.timestamp >= windowStart,
		);

		if (filteredRequests.length === 0) {
			// If no requests remain, remove the entry completely
			if (this.storage.delete) {
				await this.storage.delete(uid);
			} else {
				await this.storage.set(uid, []);
			}
		} else if (filteredRequests.length !== requests.length) {
			// Only update if there's a change
			await this.storage.set(uid, filteredRequests);
		}
	}

	/**
	 * Performs a global cleanup of all rate limit data
	 * This should be called periodically to prevent memory leaks
	 */
	async globalCleanup(): Promise<void> {
		// TODO: Implement global cleanup
	}

	/**
	 * Disposes of resources used by the rate limiter
	 */
	dispose(): void {
		if (this.cleanupTimer) {
			clearInterval(this.cleanupTimer);
			this.cleanupTimer = undefined;
		}
	}
}
