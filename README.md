# totp-hotp-ts

A TypeScript implementation of RFC4226 HOTP: An HMAC-Based One-Time Password Algorithm and RFC6238 TOTP: Time-Based One-Time Password Algorithm.

### HOTP (RFC 4226)

HOTP is a one-time password algorithm that generates a password using a counter value and a secret key. The password changes each time the counter is incremented, making it suitable for event-based authentication.

see: [RFC4226](https://datatracker.ietf.org/doc/html/rfc4226)

### TOTP (RFC 6238)

TOTP is an extension of HOTP that uses the current timestamp as the counter value. It generates a password that changes every 30 seconds (by default), making it suitable for time-based authentication like Google Authenticator.

see: [RFC6238](https://datatracker.ietf.org/doc/html/rfc6238)

## API Reference

### HOTP

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

### TOTP

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

## Example Implementation with Next.js App Router

Here's an example of how to implement TOTP verification in a Next.js application using the App Router:

1. First, create a TOTP verification API endpoint:

```typescript
// app/api/verify-totp/route.ts
import { TOTP } from "@workspace/auth/opt/totp";
import { NextResponse } from "next/server";

export async function POST(request: Request) {
  try {
    const { secret, otp } = await request.json();

    const isValid = await TOTP.verify({
      secret,
      otp,
      // Optional: customize time step and window
      step: 30,
      window: 1,
    });

    return NextResponse.json({ valid: isValid });
  } catch (error) {
    return NextResponse.json(
      { error: "Invalid request" },
      { status: 400 }
    );
  }
}
```

2. Create a TOTP verification form component:

```typescript
// app/components/TOTPVerification.tsx
"use client";

import { useState } from "react";

export function TOTPVerification() {
  const [otp, setOtp] = useState("");
  const [result, setResult] = useState<"success" | "error" | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);

    try {
      const response = await fetch("/api/verify-totp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          secret: "YOUR_BASE32_ENCODED_SECRET", // Replace with actual secret
          otp,
        }),
      });

      const data = await response.json();
      setResult(data.valid ? "success" : "error");
    } catch (error) {
      setResult("error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label htmlFor="otp" className="block text-sm font-medium">
          Enter TOTP Code
        </label>
        <input
          type="text"
          id="otp"
          value={otp}
          onChange={(e) => setOtp(e.target.value)}
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm"
          placeholder="Enter 6-digit code"
          maxLength={6}
          pattern="[0-9]{6}"
          required
        />
      </div>

      <button
        type="submit"
        disabled={loading}
        className="w-full rounded-md bg-blue-600 px-4 py-2 text-white hover:bg-blue-700 disabled:opacity-50"
      >
        {loading ? "Verifying..." : "Verify"}
      </button>

      {result === "success" && (
        <p className="text-green-600">Verification successful!</p>
      )}
      {result === "error" && (
        <p className="text-red-600">Invalid code. Please try again.</p>
      )}
    </form>
  );
}
```

3. Use the component in your page:

```typescript
// app/verify/page.tsx
import { TOTPVerification } from "../components/TOTPVerification";

export default function VerifyPage() {
  return (
    <div className="container mx-auto max-w-md p-4">
      <h1 className="mb-6 text-2xl font-bold">TOTP Verification</h1>
      <TOTPVerification />
    </div>
  );
}
```
