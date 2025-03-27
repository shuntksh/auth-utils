# Auth Utilities

A TypeScript implementation of various auth related utilities.

## Javascript Object Signing and Encryption (JOSE)

### JSON Web Token (JWT, RFC 7519)

### JSON Web Encryption (JWE, RFC7516)

### JSON Web Signature (JWS, RFC7515)

### JSON Web Key (JWK, RFC7517)

## One Time Password

### HMAC-Based One-Time Password Algorithm (HOTP, RFC 4226)

HOTP is a one-time password algorithm that generates a password using a counter value and a secret key. The password changes each time the counter is incremented, making it suitable for event-based authentication.

see: [RFC4226](https://datatracker.ietf.org/doc/html/rfc4226)

```typescript
const HOTP = {
  generate: async (options: {
    secret: string;      // Base32 encoded secret key
    counter: number;     // Counter value
    length?: number;     // Length of OTP (default: 6)
  }): Promise<string>;

  verify: async (options: {
    secret: string;      // Base32 encoded secret key
    counter: number;     // Counter value
    otp: string;        // OTP to verify
    length?: number;     // Length of OTP (default: 6)
  }): Promise<boolean>;
}
```

### Time-Based One-Time Password Algorithm (TOTP, RFC 6238)

TOTP is an extension of HOTP that uses the current timestamp as the counter value. It generates a password that changes every 30 seconds (by default), making it suitable for time-based authentication like Google Authenticator.

see: [RFC6238](https://datatracker.ietf.org/doc/html/rfc6238)

```typescript
const TOTP = {
  generate: async (options: {
    secret: string;      // Base32 encoded secret key
    time?: number;       // Current time in seconds (default: current time)
    step?: number;       // Time step in seconds (default: 30)
    length?: number;     // Length of OTP (default: 6)
  }): Promise<string>;

  verify: async (options: {
    secret: string;      // Base32 encoded secret key
    otp: string;        // OTP to verify
    time?: number;       // Current time in seconds (default: current time)
    step?: number;       // Time step in seconds (default: 30)
    length?: number;     // Length of OTP (default: 6)
    window?: number;     // Number of time steps to check (default: 1)
  }): Promise<boolean>;
}
```

## Encoding / Serialization

