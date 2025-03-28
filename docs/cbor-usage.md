# cbor-ts

A lightweight, standards-compliant TypeScript implementation of CBOR (Concise Binary Object Representation) and COSE (CBOR Object Signing and Encryption).

## Motivation

Binary data serialization is crucial for efficient data exchange in resource-constrained environments like IoT devices, embedded systems, and high-performance applications. While JSON is ubiquitous, it's not optimized for:

- **Size efficiency**: Binary formats are more compact than text-based formats
- **Processing speed**: Parsing binary data is typically faster than text
- **Rich data types**: Support for binary data, precise numeric types, and more

CBOR addresses these needs with a compact, binary representation that maintains the schema-less flexibility of JSON while adding support for binary data and a richer set of data types.

COSE extends CBOR to provide standardized cryptographic message syntax for signing and encryption, essential for secure IoT and web applications.

## What is CBOR?

[CBOR (RFC 8949)](https://datatracker.ietf.org/doc/html/rfc8949) is a binary data format inspired by JSON but designed to be:

- **Compact**: Smaller message sizes than JSON
- **Extensible**: Support for custom data types via tags
- **Self-describing**: No schema required
- **Deterministic**: Supports canonical encoding for digital signatures

CBOR supports all JSON data types plus:

- Binary data (byte strings)
- Arbitrary precision integers
- IEEE 754 floating-point values
- Distinguishable null and undefined values
- Tagged data items for extended semantics

## What is COSE?

[COSE (RFC 8152)](https://datatracker.ietf.org/doc/html/rfc8152) provides cryptographic message syntax based on CBOR, offering:

- **Digital signatures**: Single and multi-signature support
- **Message authentication codes (MACs)**: Data integrity verification
- **Encryption**: Protecting data confidentiality
- **Compact representation**: Optimized for constrained environments

COSE is widely used in:
- WebAuthn/FIDO2 authentication
- IoT security protocols
- Verifiable credentials
- OAuth token formats (CWT)

## Usage

### CBOR Encoding and Decoding

```typescript
import { CBOR } from "@workspace/auth";
// or import { CBOR } from "cbor-ts/cbor";

// Encode JavaScript values to CBOR
const encoded = CBOR.encode({
  text: "Hello, world!",
  number: 42,
  negative: -273,
  binary: new Uint8Array([0x01, 0x02, 0x03]).buffer,
  array: [1, 2, 3],
  nested: { a: 1, b: 2 },
  boolean: true,
  null: null,
  undefined: undefined,
  float: 3.14159
});

// Decode CBOR back to JavaScript values
const decoded = CBOR.decode(encoded);
console.log(decoded);
```

### COSE Sign1 (Single Signature)

```typescript
import { COSE, COSETag, HeaderParameter, Algorithm } from "@workspace/auth";
// or import { COSE, COSETag, HeaderParameter, Algorithm } from "cbor-ts/cose";

// Create a COSE_Sign1 structure
const sign1 = {
  protected: {
    [HeaderParameter.alg]: Algorithm.ES256, // ECDSA with SHA-256
    [HeaderParameter.kid]: new TextEncoder().encode("key-1").buffer
  },
  unprotected: {
    [HeaderParameter.ctyp]: "text/plain"
  },
  payload: new TextEncoder().encode("Hello, world!").buffer,
  signature: new Uint8Array([/* signature bytes */]).buffer
};

// Encode to CBOR
const encodedSign1 = COSE.Sign1.encode(sign1);

// Decode from CBOR
const decodedSign1 = COSE.Sign1.decode(encodedSign1);
```

### COSE Encrypt0 (Single Recipient Encryption)

```typescript
import { COSE, HeaderParameter, Algorithm } from "@workspace/auth";

// Create a COSE_Encrypt0 structure
const encrypt0 = {
  protected: {
    [HeaderParameter.alg]: Algorithm.AES_GCM_256
  },
  unprotected: {
    [HeaderParameter.iv]: new Uint8Array([/* IV bytes */]).buffer
  },
  ciphertext: new Uint8Array([/* encrypted data */]).buffer
};

// Encode to CBOR
const encodedEncrypt0 = COSE.Encrypt0.encode(encrypt0);

// Decode from CBOR
const decodedEncrypt0 = COSE.Encrypt0.decode(encodedEncrypt0);
```

## Features

- **Full RFC compliance**: Implements RFC 8949 (CBOR) and RFC 8152 (COSE)
- **Deterministic encoding**: Ensures consistent output for digital signatures
- **Comprehensive type support**: All CBOR data types and COSE structures
- **TypeScript-first**: Full type definitions for all APIs
- **Zero dependencies**: Lightweight and self-contained
- **Browser and Node.js compatible**: Works in any JavaScript environment

## Limitations

- Maximum input size limited to 16MB to prevent memory exhaustion
- No streaming support; all data is processed in memory
- No cryptographic operations; this is a structural encoding/decoding library only

