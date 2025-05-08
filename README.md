# PinAuth (WIP)

## Overview

`PinAuth` is a lightweight, local-first cryptographic authentication helper designed for environments where offline login via PIN is required like POS system It supports:

* HMAC-based PIN hashing and verification
* Envelope encryption/decryption using a device key
* Secure client-side storage using IndexedDB (if available)
* Configurable setup with organization ID, salt, and storage name

This package works both in the browser and on the server (with Web Crypto API support).

### Use this with other authentication methods

---

## Installation

install using npm, bun or any package manager:

```ts
bun i pin-auth
```

then

```ts
import { PinAuth } from 'pin-auth';
```

---

## Interfaces

```ts
export interface PinAuthConfig {
  orgId: string;
  salt?: Uint8Array;
  deviceKeyRaw?: Uint8Array;
  deviceKeyString?: string;
  localDbName?: string;
}

export interface AuthObject {
  h: string; // HMAC hash
  s: string; // Salt used for HMAC
}

export interface AuthDataType {
  auth: AuthObject;
  [key: string]: any;
}
```

---

## Constructor

```ts
new PinAuth(config: PinAuthConfig)
```

* `orgId` – Unique string per organization (used as PBKDF2 password input)
* `salt` – Optional salt (random 16-byte array will be generated if not provided)
* `deviceKeyRaw` – Optional AES key as a raw Uint8Array (takes precedence over string)
* `deviceKeyString` – Optional device key string (e.g., a Firestore document ID). If provided, it will be automatically set and used.
* `localDbName` – Optional name for IndexedDB database (defaults to `pin-auth-store`)

> **Note:** `deviceKey` must be provided at instantiation time via `deviceKeyString` or `deviceKeyRaw`. It cannot be set later.

---

## Methods

### PIN Management (Server-Side or Admin Flow)

#### `encryptPin(pin: string): Promise<{ auth: { h: string, s: string } }>`

* Hashes a plain PIN using HMAC (derived from orgId and salt)
* Returns an object with an `auth` property containing:

  * `h`: base64 HMAC hash
  * `s`: base64-encoded salt

#### `verifyPin(pin: string): Promise<any | null>`

* Takes a plain PIN string and compares it against locally stored encrypted user data
* Internally decrypts and iterates over stored records in IndexedDB
* Verifies the `auth.h` with the provided PIN and the corresponding `auth.s`
* Returns the full user object if a match is found; otherwise returns `null`

---

### Local Data Storage (Client-Side)

#### `addPinAuthData(data: AuthDataType[]): Promise<void>`

* Encrypts and stores an array of user data to local IndexedDB
* Requires a device key to be set
* Each object should contain an `auth` object as described in `encryptPin`

#### `updatePinAuthData(data: AuthDataType[]): Promise<void>`

* Updates existing encrypted PIN auth data

#### `clearPinAuthData(): Promise<void>`

* Clears stored PIN auth data from IndexedDB

---

## Example Usage

### On the Server (Admin Setup)

```ts
const auth = new PinAuth({ orgId: 'org_123' });
const { auth: authObject } = await auth.encryptPin('123456');
// Save user object like { id: 'user1', name: 'Anna', auth: authObject } to the database
```

### On the Client (POS Device Setup)

```ts
const deviceKey = 'abc123firestoreDocId';
const auth = new PinAuth({ orgId: 'org_123', deviceKeyString: deviceKey });

// Store user data locally after initial sync
await auth.addPinAuthData([
  { id: 'user1', name: 'Anna', auth: { h: '...', s: '...' } },
  { id: 'user2', name: 'Ben', auth: { h: '...', s: '...' } },
]);
```

### Verifying PIN Locally Without Knowing the User

```ts
const matchedUser = await auth.verifyPin('123456');

if (matchedUser) {
  console.log('Logged in as:', matchedUser.name);
} else {
  console.log('Invalid PIN');
}
```

### Updating Local Data

```ts
await auth.updatePinAuthData(updatedUserDataArray);
```

### Clearing Local Data

```ts
await auth.clearPinAuthData();
```

---

## Security Notes

* PBKDF2 with HMAC-SHA256 is used to derive the HMAC key
* Salt should be random per org if high isolation is required
* Device keys can be strings or raw bytes; strings are UTF-8 encoded and padded to 32 bytes
* AES-GCM with a new IV is used for every encryption
* IndexedDB is used only in browser environments
* Ensure the Firestore document ID used as device key remains secret on the client
* Stored user data should include the `auth` object with `h` and `s` for secure PIN matching

---

## License

MIT
