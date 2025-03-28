# Signed URL Utility

This module provides functionality for creating and verifying signed URLs, similar to the signed URL functionality provided by cloud storage services like AWS S3 or Google Cloud Storage.

## Features

- Create signed URLs with configurable expiration times
- Verify signed URLs to ensure they are valid and not expired
- Protection against tampering with URL parameters
- Optional nonce support for preventing replay attacks
- Configurable logging for security monitoring
- Constant-time comparison for signature verification to prevent timing attacks
- Object-oriented parameter handling with `SignedSearchParams` class

## How It Works

Signed URLs work by adding a cryptographic signature to URL query parameters, allowing servers to verify that:

1. The URL was created by someone with access to the secret key
2. The URL has not been tampered with
3. The URL has not expired
4. (Optional) The URL has not been used before (with nonce verification)

The signature is created by:
1. Combining the URL's hostname, path, and query parameters (excluding the signature itself)
2. Signing this string with HMAC-SHA256 using the secret key
3. Adding the signature as a query parameter (`X-Signature`)

When verifying, the server recalculates the signature using the same process and compares it to the provided signature.

## Public Interface

### Main Functions

The module exports two main functions:

- `createSignedUrl`: Creates a signed URL with expiration and optional parameters
- `verifySignedUrl`: Verifies a signed URL to ensure it's valid and not expired

### SignedSearchParams Class

The module also exports a `SignedSearchParams` class that handles URL parameter manipulation:

- Provides a clean interface for working with signed URL parameters
- Encapsulates parameter validation and manipulation logic
- Supports fluent method chaining for better readability

## Usage

### Creating a Signed URL

```typescript
import { createSignedUrl } from "@workspace/auth/requests/signed-url";

// Basic usage with default options (15-minute expiration)
const params = await createSignedUrl(
  "https://example.com/resource/123",
  "your-access-key",
  "your-secret-key"
);

// Convert to a full URL string
const url = new URL("https://example.com/resource/123");
for (const [key, value] of params.entries()) {
  url.searchParams.set(key, value);
}
const signedUrlString = url.toString();
```

### With Custom Options

```typescript
// With custom expiration and additional parameters
const params = await createSignedUrl(
  "https://example.com/resource/123",
  "your-access-key",
  "your-secret-key",
  {
    // Set expiration to 1 hour
    expiresIn: 3600,
    // Set maximum allowed expiration (optional)
    maxExpiresIn: 24 * 3600, // 24 hours
    // Add custom query parameters
    queryParams: {
      action: "download",
      version: "1.0"
    },
    // Add a nonce for replay attack prevention
    nonce: "unique-random-string"
  }
);
```

### Verifying a Signed URL

```typescript
import { verifySignedUrl } from "@workspace/auth/requests/signed-url";

// Verify a URL object
const urlObj = new URL("https://example.com/resource/123?X-Key=...");
const result = await verifySignedUrl(
  urlObj,
  "your-access-key",
  "your-secret-key"
);

if (result.valid) {
  // URL is valid and not expired
  // Process the request
} else {
  // URL is invalid or expired
  console.error(`Invalid signed URL: ${result.reason}`);
}
```

### With Logging and Nonce Verification

```typescript
// With logging and nonce verification
const result = await verifySignedUrl(
  urlObj,
  "your-access-key",
  "your-secret-key",
  {
    // Verify the nonce matches
    nonce: "unique-random-string",
    // Log verification results
    logger: (info) => {
      console.log(`Signed URL verification: ${info.valid ? 'success' : 'failure'}`);
      if (!info.valid) {
        console.error(`Reason: ${info.reason}`);
        console.debug('Context:', info.context);
      }
    }
  }
);
```

### Using SignedSearchParams Directly

For advanced use cases, you can use the `SignedSearchParams` class directly:

```typescript
import { SignedSearchParams } from "@workspace/auth/requests/signed-url";

// Create a new instance
const params = new SignedSearchParams();

// Set required parameters
params.setSignedUrlParams(
  "your-access-key",
  Math.floor(Date.now() / 1000) + 3600, // Expires in 1 hour
  new URL("https://example.com/resource/123"),
  "unique-nonce"
);

// Add custom parameters
params.addQueryParams({
  action: "download",
  version: "1.0"
});

// Generate a string to sign
const stringToSign = params.createStringToSign(
  "example.com",
  "/resource/123"
);

// Convert to URLSearchParams
const urlParams = params.toURLSearchParams();
```

## Common Use Cases

### Secure Download Links

Generate time-limited download links for private content:

```typescript
// Generate a download link that expires in 24 hours
const params = await createSignedUrl(
  "https://storage.example.com/private/file.pdf",
  accessKey,
  secretKey,
  {
    expiresIn: 24 * 3600,
    queryParams: {
      action: "download",
      filename: "important-document.pdf"
    }
  }
);
```

### Form Submissions

Prevent CSRF attacks by requiring signed form submission URLs:

```typescript
// Generate a signed URL for a form submission
const formUrl = await createSignedUrl(
  "https://api.example.com/submit-form",
  accessKey,
  secretKey,
  {
    expiresIn: 15 * 60, // 15 minutes
    nonce: crypto.randomUUID() // Prevent replay attacks
  }
);
```

### API Access Control

Control access to API endpoints with signed URLs:

```typescript
// Generate a signed URL for API access
const apiUrl = await createSignedUrl(
  "https://api.example.com/v1/data",
  accessKey,
  secretKey,
  {
    expiresIn: 5 * 60, // 5 minutes
    queryParams: {
      limit: "100",
      format: "json"
    }
  }
);
```

## Best Practices

### Secret Key Management

- **Never expose your secret key in client-side code**
- Store secret keys securely using environment variables or a secrets management service
- Consider using a key rotation strategy for long-lived applications

```typescript
// Example using environment variables
const secretKey = process.env.SIGNED_URL_SECRET_KEY;
if (!secretKey) {
  throw new Error("Missing required environment variable: SIGNED_URL_SECRET_KEY");
}
```

### Expiration Times

- Use short expiration times appropriate for your use case
- Recommended ranges:
  - Short-lived operations (form submissions): 5-15 minutes
  - Download links: 1-24 hours
  - Long-running operations: Up to 7 days (with caution)

### Replay Attack Prevention

For sensitive operations, use the nonce parameter and verify it server-side:

1. Generate a unique nonce for each signed URL
2. Store the nonce in a database or cache with the same expiration as the URL
3. When verifying, check that the nonce exists and hasn't been used before
4. Delete or mark the nonce as used after successful verification

```typescript
// Example nonce verification with Redis
import { createClient } from 'redis';

const redis = createClient();
await redis.connect();

// When creating a signed URL
const nonce = crypto.randomUUID();
await redis.set(`signed-url-nonce:${nonce}`, '1', {
  EX: expiresIn // Set expiration in seconds
});

// When verifying
const urlNonce = params.get('X-Nonce');
if (!urlNonce) {
  return { valid: false, reason: 'Missing nonce' };
}

const nonceExists = await redis.get(`signed-url-nonce:${urlNonce}`);
if (!nonceExists) {
  return { valid: false, reason: 'Invalid or already used nonce' };
}

// Delete the nonce to prevent reuse
await redis.del(`signed-url-nonce:${urlNonce}`);
```

### Security Monitoring

Use the logger option to monitor verification failures, which could indicate attempted attacks:

```typescript
// Example with structured logging
const logger = (info) => {
  if (!info.valid) {
    const logEntry = {
      level: 'warn',
      message: `Signed URL verification failed: ${info.reason}`,
      timestamp: new Date().toISOString(),
      ...info.context,
      // Add request metadata
      ip: request.ip,
      userAgent: request.headers['user-agent'],
      path: request.path
    };
    
    // Log to your monitoring system
    console.warn(JSON.stringify(logEntry));
  }
};
```

## Error Handling

The module throws specific error types that you can catch and handle:

- `SignedUrlParamError`: Thrown when query parameters don't conform to the expected shape
- `Error`: Generic errors during URL creation or verification

```typescript
try {
  const params = await createSignedUrl(url, key, secret, options);
} catch (error) {
  if (error instanceof SignedUrlParamError) {
    // Handle parameter validation errors
  } else {
    // Handle other errors
  }
}
```

## Performance Considerations

- HMAC-SHA256 computation is relatively fast but can become a bottleneck under high load
- Consider implementing a signature cache for frequently accessed resources
- The `SignedSearchParams` class provides efficient parameter handling
- Profile your application to identify performance bottlenecks
