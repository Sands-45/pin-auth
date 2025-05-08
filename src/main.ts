import Dexie, { Table } from "dexie";
import {
  AuthDataType,
  AuthObject,
  PinAuthConfig,
  PinAuthRecord,
} from "./types";

export class PinAuth {
  private orgId: string;
  private salt: Uint8Array;
  private deviceKey: CryptoKey | null = null;
  private hmacKeyPromise: Promise<CryptoKey>;
  private localDbName: string;
  private deviceKeyInitializationPromise: Promise<void>;

  private db: Dexie & { pins: Table<PinAuthRecord, any> };

  constructor(config: PinAuthConfig) {
    this.orgId = config.orgId;
    this.salt = config.salt ?? crypto.getRandomValues(new Uint8Array(16));
    this.localDbName = config.localDbName ?? "pin-auth-store";

    this.db = new Dexie(this.localDbName) as Dexie & {
      pins: Table<PinAuthRecord, any>;
    };
    this.db.version(1).stores({
      pins: "id", // Primary key
    });

    let rawKeyToImport: Uint8Array | undefined;
    if (config.deviceKeyRaw) {
      rawKeyToImport = config.deviceKeyRaw;
    } else if (config.deviceKeyString) {
      rawKeyToImport = new TextEncoder().encode(
        config.deviceKeyString.padEnd(32, "_")
      );
    }

    if (rawKeyToImport) {
      this.deviceKeyInitializationPromise =
        this.importDeviceKey(rawKeyToImport);
    } else {
      // If no key to import, deviceKey remains null.
      // Initialize promise to resolved so await doesn't hang.
      this.deviceKeyInitializationPromise = Promise.resolve();
    }

    this.hmacKeyPromise = this.deriveHmacKey();
  }

  private async importDeviceKey(rawKey: Uint8Array): Promise<void> {
    this.deviceKey = await crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  private async deriveHmacKey(): Promise<CryptoKey> {
    const baseKey = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(this.orgId),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: this.salt,
        iterations: 100_000,
        hash: "SHA-256",
      },
      baseKey,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign", "verify"]
    );
  }

  // Hashes a PIN and returns the auth object
  async encryptPin(pin: string): Promise<{ auth: AuthObject }> {
    const key = await this.hmacKeyPromise;
    const signature = await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(pin)
    );
    return {
      auth: {
        h: btoa(String.fromCharCode(...new Uint8Array(signature))),
        s: btoa(String.fromCharCode(...this.salt)),
      },
    };
  }

  // Verifies a PIN against locally stored encrypted data
  async verifyPin(pin: string): Promise<AuthDataType | null> {
    await this.deviceKeyInitializationPromise;

    if (!this.deviceKey) {
      console.error("Device key not initialized. Cannot verify PIN.");
      return null;
    }

    const allStoredRecords = await this.db.pins.toArray();

    if (!allStoredRecords || allStoredRecords.length === 0) return null;

    for (const storedRecord of allStoredRecords) {
      try {
        const iv = Uint8Array.from(atob(storedRecord.iv), (c) =>
          c.charCodeAt(0)
        );
        const ciphertext = Uint8Array.from(atob(storedRecord.ciphertext), (c) =>
          c.charCodeAt(0)
        );

        const decryptedBuffer = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv },
          this.deviceKey,
          ciphertext
        );

        const decryptedJson = new TextDecoder().decode(decryptedBuffer);
        const decryptedRecord = JSON.parse(decryptedJson) as AuthDataType;

        const { h, s } = decryptedRecord.auth;
        const keyFromStoredSalt = await this.deriveKeyFromSalt(atob(s));
        const signatureToVerify = await crypto.subtle.sign(
          "HMAC",
          keyFromStoredSalt,
          new TextEncoder().encode(pin)
        );
        const actualSignature = new Uint8Array(signatureToVerify);
        const expectedSignature = Uint8Array.from(atob(h), (c) =>
          c.charCodeAt(0)
        );

        if (
          actualSignature.length === expectedSignature.length &&
          actualSignature.every((val, i) => val === expectedSignature[i])
        ) {
          // user data without auth values
          const userData = { ...decryptedRecord, auth: { h: "", s: "" } };
          return userData;
        }
      } catch (error) {
        console.error("Error during PIN verification for a record:", error);
        // Continue to the next record if one fails (e.g., decryption error)
      }
    }
    return null;
  }

  private async deriveKeyFromSalt(saltString: string): Promise<CryptoKey> {
    const salt = Uint8Array.from(saltString, (c) => c.charCodeAt(0));
    const baseKey = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(this.orgId),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: 100_000,
        hash: "SHA-256",
      },
      baseKey,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign", "verify"]
    );
  }

  async addPinAuthData(data: AuthDataType[]): Promise<void> {
    await this.deviceKeyInitializationPromise;
    if (!this.deviceKey)
      throw new Error("Device key not set or failed to initialize.");

    try {
      const recordsToPut: PinAuthRecord[] = [];
      for (const user of data) {
        const json = JSON.stringify(user);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const enc = new TextEncoder().encode(json);
        const ciphertext = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv },
          this.deviceKey,
          enc
        );
        recordsToPut.push({
          id: user.id,
          iv: btoa(String.fromCharCode(...iv)),
          ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
        });
      }
      // bulkPut will add or overwrite
      await this.db.pins.bulkPut(recordsToPut);
    } catch (error) {
      console.error("Error in addPinAuthData:", error);
      throw error;
    }
  }

  async updatePinAuthData(data: AuthDataType[]): Promise<void> {
    return this.addPinAuthData(data);
  }

  async clearPinAuthData(): Promise<void> {
    await this.db.pins.clear();
  }
}
