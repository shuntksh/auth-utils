# Rate Limiter

A production-grade rate limiter implementation for protecting APIs and services from abuse and DDoS attacks.

## Features

- **Sliding Window Algorithm**: More accurate than fixed window counters
- **Global Policy Configuration**: Define and reuse rate limit policies across your application
- **Flexible Storage Options**: Use the built-in LRU cache or provide your own storage adapter
- **Violation Tracking**: Monitor and respond to clients that repeatedly exceed rate limits
- **Automatic Cleanup**: Prevent memory leaks with configurable cleanup intervals
- **High Performance**: Optimized for minimal overhead in high-traffic environments
- **DDoS Protection**: Helps mitigate distributed denial-of-service attacks

## Usage

### Basic Usage

```typescript
import { RateLimiter } from "./rate-limiter";

// Create a rate limiter with default options
const limiter = new RateLimiter();

// Register a global policy
limiter.registerPolicy("api", { 
  windowMs: 60000,  // 1 minute
  maxRequests: 100  // 100 requests per minute
});

// Check if a request is allowed
const result = await limiter.check("client-id", "api");

if (result.success) {
  // Request is allowed
  console.log(`Remaining requests: ${result.remaining}`);
} else {
  // Request is rate limited
  console.log(`Try again after: ${new Date(result.resetTime)}`);
}
```

### Advanced Configuration

```typescript
import { RateLimiter } from "./rate-limiter";
import { LRUCache } from "./lru";

// Create a rate limiter with advanced options
const limiter = new RateLimiter({
  // Pre-define policies
  defaultPolicies: {
    "api": { windowMs: 60000, maxRequests: 100 },
    "auth": { windowMs: 60000, maxRequests: 10 },
  },
  
  // Custom storage with TTL
  storage: new LRUCache(10000, {
    ttl: 600000,  // 10 minutes
    ttlAutoPurge: true,
  }),
  
  // Track violations
  trackViolations: true,
  
  // Cleanup every 5 minutes
  cleanupInterval: 300000,
});

// Check using a policy ID
await limiter.check("client-id", "api");

// Or check using a custom policy
await limiter.check("client-id", { 
  windowMs: 30000,
  maxRequests: 5
});
```

### Middleware Example

```typescript
// See rate-limiter-usage-example.ts for a complete middleware example
import { rateLimitMiddleware } from "./rate-limiter-usage-example";

// Use in Express.js
app.use(rateLimitMiddleware);
```

## API Reference

### `RateLimiter`

The main class for rate limiting.

#### Constructor

```typescript
constructor(options?: RateLimiterOptions)
```

Options:
- `defaultPolicies`: Record of named policies
- `storage`: Custom storage adapter
- `useTokenBucket`: Enable token bucket algorithm
- `cleanupInterval`: Interval for automatic cleanup
- `trackViolations`: Track rate limit violations
- `maxViolationsTracked`: Maximum number of violators to track

#### Methods

- `registerPolicy(policyId: string, policy: RateLimitPolicy): void`
- `removePolicy(policyId: string): boolean`
- `getPolicies(): Record<string, RateLimitPolicy>`
- `check(uid: string, policyIdOrPolicy: string | RateLimitPolicy): Promise<RateLimitResponse>`
- `cleanup(uid: string, windowMs: number): Promise<void>`
- `globalCleanup(): Promise<void>`
- `getViolationCount(uid: string): number`
- `getTopViolators(limit?: number): Array<{ uid: string; count: number }>`
- `dispose(): void`

### Types

```typescript
interface RateLimitPolicy {
  windowMs: number;    // Window size in milliseconds
  maxRequests: number; // Maximum requests allowed in the window
}

interface RateLimitResponse {
  success: boolean;    // Whether the request is allowed
  remaining: number;   // Remaining requests in the current window
  resetTime: number;   // Time when the rate limit resets
}
```

## Best Practices

1. **Use Different Policies for Different Endpoints**
   - Apply stricter limits to authentication endpoints
   - Allow more requests for public/read-only endpoints

2. **Combine IP and User-Based Rate Limiting**
   - Limit by IP address for unauthenticated requests
   - Limit by user ID for authenticated requests

3. **Set Appropriate Headers**
   - Include rate limit information in response headers
   - Use standard headers like `X-RateLimit-Limit`, `X-RateLimit-Remaining`

4. **Monitor Violations**
   - Track clients that repeatedly exceed rate limits
   - Implement escalating responses for abusive clients

5. **Use a Distributed Storage**
   - For multi-server deployments, use Redis or similar for storage
   - Implement a custom storage adapter for your environment

## Security Considerations

- **IP Spoofing**: Be aware that IP addresses can be spoofed
- **Proxy Awareness**: Use `X-Forwarded-For` headers when behind proxies
- **Graceful Degradation**: Don't crash if the rate limiter fails
- **Avoid Information Leakage**: Don't expose sensitive information in error responses

## Performance Tuning

- Adjust the LRU cache size based on your traffic patterns
- Set appropriate TTL values to prevent memory growth
- Use the cleanup interval to periodically free resources
- Consider implementing a token bucket algorithm for burst of traffic 