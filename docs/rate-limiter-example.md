# Example Usage

```ts
import { LRUCache } from "./lru";
import { RateLimiter } from "./rate-limiter";
import type { RateLimitPolicy, RateLimitResponse, RequestEntry } from "./types";

/**
 * Example of how to use the enhanced RateLimiter in a production environment
 *
 * This example demonstrates:
 * 1. Setting up global policies for different API endpoints
 * 2. Using the rate limiter in an API request handler
 * 3. Implementing IP-based and user-based rate limiting
 * 4. Handling rate limit responses
 */

// Define common rate limit policies
const commonPolicies: Record<string, RateLimitPolicy> = {
	// General API rate limit (100 requests per minute)
	api: {
		windowMs: 60 * 1000, // 1 minute
		maxRequests: 100,
	},

	// Authentication endpoints (10 requests per minute)
	auth: {
		windowMs: 60 * 1000, // 1 minute
		maxRequests: 10,
	},

	// Search endpoints (30 requests per minute)
	search: {
		windowMs: 60 * 1000, // 1 minute
		maxRequests: 30,
	},

	// Admin endpoints (200 requests per minute)
	admin: {
		windowMs: 60 * 1000, // 1 minute
		maxRequests: 200,
	},
};

// Create a rate limiter instance with global policies
const rateLimiter = new RateLimiter({
	// Use the common policies as defaults
	defaultPolicies: commonPolicies,

	// Use a custom LRU cache with TTL for automatic cleanup
	storage: new LRUCache<RequestEntry[]>(10000, {
		ttl: 10 * 60 * 1000, // 10 minutes TTL
		ttlAutoPurge: true,
	}),

	// Enable tracking of rate limit violations
	trackViolations: true,

	// Set a cleanup interval (5 minutes)
	cleanupInterval: 5 * 60 * 1000,

	// Maximum number of violators to track
	maxViolationsTracked: 1000,
});

/**
 * Types for the middleware example
 */
interface Request {
	ip?: string;
	path: string;
	user?: { id: string };
	connection?: { remoteAddress: string };
}

interface Response {
	setHeader(name: string, value: string | number): void;
	status(code: number): Response;
	json(body: unknown): Response;
}

type NextFunction = () => void;

/**
 * Example middleware function for Express.js or similar frameworks
 * This demonstrates how to use the rate limiter in an API request handler
 */
async function rateLimitMiddleware(
	req: Request,
	res: Response,
	next: NextFunction,
) {
	try {
		// Get client IP address
		const clientIp = req.ip || req.connection.remoteAddress;

		// Get user ID if authenticated
		const userId = req.user?.id;

		// Determine which policy to use based on the request path
		let policyId = "api"; // Default policy

		if (req.path.startsWith("/api/auth")) {
			policyId = "auth";
		} else if (req.path.startsWith("/api/search")) {
			policyId = "search";
		} else if (req.path.startsWith("/api/admin")) {
			policyId = "admin";
		}

		// Apply IP-based rate limiting
		const ipResult = await rateLimiter.check(`ip:${clientIp}`, policyId);

		// If IP is rate limited, return 429 Too Many Requests
		if (!ipResult.success) {
			return sendRateLimitResponse(res, ipResult);
		}

		// If user is authenticated, also apply user-based rate limiting
		if (userId) {
			const userResult = await rateLimiter.check(`user:${userId}`, policyId);

			// If user is rate limited, return 429 Too Many Requests
			if (!userResult.success) {
				return sendRateLimitResponse(res, userResult);
			}
		}

		// Add rate limit headers to the response
		addRateLimitHeaders(res, ipResult);

		// Continue to the next middleware or route handler
		next();
	} catch (error) {
		// Log the error and continue (don't block requests if rate limiter fails)
		console.error("Rate limiter error:", error);
		next();
	}
}

/**
 * Helper function to send a rate limit exceeded response
 */
function sendRateLimitResponse(res: Response, result: RateLimitResponse) {
	// Add rate limit headers
	addRateLimitHeaders(res, result);

	// Calculate retry-after time in seconds
	const retryAfterSeconds = Math.ceil((result.resetTime - Date.now()) / 1000);

	// Set retry-after header
	res.setHeader("Retry-After", retryAfterSeconds.toString());

	// Send 429 Too Many Requests response
	return res.status(429).json({
		error: "Too Many Requests",
		message: "Rate limit exceeded. Please try again later.",
		retryAfter: retryAfterSeconds,
	});
}

/**
 * Helper function to add rate limit headers to the response
 */
function addRateLimitHeaders(res: Response, result: RateLimitResponse) {
	res.setHeader("X-RateLimit-Limit", result.remaining + 1);
	res.setHeader("X-RateLimit-Remaining", result.remaining);
	res.setHeader("X-RateLimit-Reset", result.resetTime);
}

/**
 * Example of how to monitor and handle frequent violators
 * This could be run periodically to detect and block abusive clients
 */
async function monitorRateLimitViolations() {
	// Get the top 10 violators
	const topViolators = rateLimiter.getTopViolators(10);

	console.log("Top rate limit violators:", topViolators);

	// Example: Block IPs with more than 100 violations
	for (const violator of topViolators) {
		if (violator.count > 100 && violator.uid.startsWith("ip:")) {
			const ip = violator.uid.substring(3);
			console.log(`Blocking IP ${ip} due to excessive rate limit violations`);

			// Here you would add the IP to a block-list or firewall rule
			// This is just a placeholder for demonstration
			// await blockIpAddress(ip);
		}
	}
}

// Example: Run the violation monitor every hour
// setInterval(monitorRateLimitViolations, 60 * 60 * 1000);

// Export for demonstration purposes
export { monitorRateLimitViolations, rateLimiter, rateLimitMiddleware };
```