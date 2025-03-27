# @auth-utils/cbor

This package provides a TypeScript/Node.js implementation of the **Concise Binary Object Representation (CBOR)** and **CBOR Object Signing and Encryption (COSE)** standards. It enables efficient serialization and cryptographic operations for compact, binary data exchange.

## Concise Binary Object Representation (CBOR, RFC 8949)

CBOR is a binary data serialization format designed for small code size, minimal message size, and extensibility without version negotiation. It is ideal for constrained environments and supports a wide range of data types, including numbers, strings, arrays, maps, and binary data.

See: [RFC 8949](https://datatracker.ietf.org/doc/html/rfc8949)

### Usage
The `CBOR` module provides simple methods to encode and decode data:

```typescript
import { CBOR } from '@auth-utils/cbor';

const data = { Hello: "World", Number: 42 };
const encoded = CBOR.encode(data); // Returns an ArrayBuffer
const decoded = CBOR.decode(encoded); // Returns the original object
console.log(decoded); // { Hello: "World", Number: 42 }
```

## CBOR Object Signing and Encryption (COSE, RFC 8152)

COSE builds on CBOR to provide cryptographic services such as signing, encryption, and message authentication. It is designed for secure data exchange in constrained environments, leveraging CBOR's binary efficiency. This package implements COSE structures like `COSE_Sign`, `COSE_Sign1`, `COSE_Encrypt`, `COSE_Encrypt0`, `COSE_Mac`, and `COSE_Mac0`, along with key management utilities.

See: [RFC 8152](https://datatracker.ietf.org/doc/html/rfc8152)

### Usage
The `COSE` module supports signing and encryption operations. Below is an example of signing a message with a single signer using `COSE_Sign1`:

```typescript
import { COSE, Key } from '@auth-utils/cbor';

// Example key (simplified for demonstration)
const coseKey: COSEKey = {
  1: 2, // kty: EC2
  3: -7, // alg: ES256 (ECDSA w/ SHA-256)
  [-1]: 1, // crv: P-256
  [-2]: new Uint8Array([...]), // x coordinate (public key)
  [-3]: new Uint8Array([...]), // y coordinate (public key)
};

// Create a COSE_Sign1 message
const sign1: COSE_Sign1 = {
  protected: { 1: -7 }, // alg: ES256
  unprotected: { 4: "example-key-id" }, // kid
  payload: new TextEncoder().encode("This is the content."),
  signature: new ArrayBuffer(0), // Placeholder, will be computed
};

// Encode the signed message
const signedMessage = Sign1.encode(sign1); // Returns an ArrayBuffer

// Decode and verify
const decodedSign1 = Sign1.decode(signedMessage);
console.log(new TextDecoder().decode(decodedSign1.payload)); // "This is the content."
```

For encryption, key management, or multi-signer scenarios, refer to the `Encrypt`, `Encrypt0`, `Mac`, `Mac0`, and `Key` modules in the codebase.

## Installation

Install the package via npm:

```bash
npm install @auth-utils/cbor
```

## Features

- **CBOR Encoding/Decoding**: Full support for CBOR data types (RFC 8949).
- **COSE Structures**: Signing (`COSE_Sign`, `COSE_Sign1`), encryption (`COSE_Encrypt`, `COSE_Encrypt0`), and MAC (`COSE_Mac`, `COSE_Mac0`).
- **TypeScript Support**: Fully typed for seamless integration in TypeScript projects.
- **Node.js Compatibility**: Leverages Node.js Buffer and ArrayBuffer for binary operations.

## Notes

- Ensure cryptographic keys are securely managed; refer to `cose/key.ts` for COSE key structure details.
- The implementation follows the specifications in RFC 8949 and RFC 8152, with code organized in `cbor/` and `cose/` directories.

## License

[MIT License](LICENSE)
