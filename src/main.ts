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
  private default_db_name = "pin-auth-store";
  static readonly version = "0.0.3";

  constructor(config: PinAuthConfig) {
    this.orgId = config.orgId;
    this.salt = config.salt ?? crypto.getRandomValues(new Uint8Array(16));
    this.localDbName = config.localDbName ?? this.default_db_name;

    this.db = new Dexie(this.localDbName) as Dexie & {
      pins: Table<PinAuthRecord, any>;
    };
    this.db.version(1).stores({
      pins: "id",
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

  /* Update config function if PinAuth is already initialized else ask user
     to initialize before using updatePinAuthConfig
  */
  async reinitializePinAuth(config: PinAuthConfig): Promise<PinAuth> {
    // Update core configuration that affects HMAC key derivation
    this.orgId = config.orgId;
    // Use salt from config if provided, otherwise generate a new random salt
    this.salt = config.salt ?? crypto.getRandomValues(new Uint8Array(16));

    // Update localDbName only if explicitly provided in the config
    if (config.localDbName !== undefined) {
      this.localDbName = config.localDbName;
      // Reinitialize the database with the new name
      this.db = new Dexie(config.localDbName) as Dexie & {
        pins: Table<PinAuthRecord, any>;
      };
      this.db.version(1).stores({
        pins: "id",
      });
    }

    // Re-derive HMAC key as orgId or salt has changed
    this.hmacKeyPromise = this.deriveHmacKey();

    // Clear existing PIN data as it's tied to the
    //old orgId/salt configuration
    await this.clearPinAuthData();

    // Handle device key
    const wantsToSetDeviceKey = config.deviceKeyRaw || config.deviceKeyString;

    if (this.deviceKey) {
      // Device key is already set.
      if (wantsToSetDeviceKey) {
        console.warn(
          "Device key is already set and cannot be changed via updatePinAuthConfig. " +
            "Ignoring new device key parameters. To change the device key, reinitialize PinAuth."
        );
      }
    } else {
      // No deviceKey currently set. Try to initialize if provided in config.
      let rawKeyToImport: Uint8Array | undefined;
      if (config.deviceKeyRaw) {
        rawKeyToImport = config.deviceKeyRaw;
      } else if (config.deviceKeyString) {
        rawKeyToImport = new TextEncoder().encode(
          config.deviceKeyString.padEnd(32, "_")
        );
      }

      if (rawKeyToImport) {
        // Import the new device key.
        this.deviceKeyInitializationPromise =
          this.importDeviceKey(rawKeyToImport);
        await this.deviceKeyInitializationPromise;
      }
    }

    // return the updated instance
    return this;
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

  // Verifies a PIN against a provided AuthDataType object
  async verifyPin(pin: string): Promise<AuthDataType | null> {
    await this.deviceKeyInitializationPromise;

    if (!this.deviceKey) {
      console.error(
        "Device key not initialized. Cannot verify PIN against stored data."
      );
      return null;
    }

    const allDecryptedRecords = await this.getAllDecryptedPinAuthData();

    if (!allDecryptedRecords || allDecryptedRecords.length === 0) {
      // No data to verify against, or device key was not available for
      // \ getAllDecryptedPinAuthData
      return null;
    }

    for (const decryptedRecord of allDecryptedRecords) {
      if (
        !decryptedRecord.auth ||
        !decryptedRecord.auth.h ||
        !decryptedRecord.auth.s
      ) {
        console.warn(
          "Skipping record due to missing auth data:",
          decryptedRecord.id
        );
        continue;
      }
      try {
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
          const { auth, ...userData } = decryptedRecord;
          return userData as AuthDataType;
        }
      } catch (error) {
        console.error(
          `Error during PIN verification for record ${decryptedRecord.id}:`,
          error
        );
      }
    }
    return null;
  }

  private async decryptRecord(
    storedRecord: PinAuthRecord
  ): Promise<AuthDataType | null> {
    if (!this.deviceKey) {
      // This check is more of a safeguard; deviceKey should be
      //  ensured by calling methods.
      console.error("Device key not available for decryption.");
      return null;
    }
    try {
      const iv = Uint8Array.from(atob(storedRecord.iv), (c) => c.charCodeAt(0));
      const ciphertext = Uint8Array.from(atob(storedRecord.ciphertext), (c) =>
        c.charCodeAt(0)
      );

      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        this.deviceKey,
        ciphertext
      );

      const decryptedJson = new TextDecoder().decode(decryptedBuffer);
      return JSON.parse(decryptedJson) as AuthDataType;
    } catch (error) {
      console.error("Error decrypting record:", error);
      return null;
    }
  }

  // Retrieves and decrypts a single user's data by ID
  async getDecryptedPinAuthDataById(id: string): Promise<AuthDataType | null> {
    await this.deviceKeyInitializationPromise;
    if (!this.deviceKey) {
      console.error(
        "Device key not initialized. Cannot get decrypted PIN auth data."
      );
      return null;
    }

    const storedRecord = await this.db.pins.get(id);
    if (!storedRecord) return null;

    return this.decryptRecord(storedRecord);
  }

  // Retrieves and decrypts all stored user data
  async getAllDecryptedPinAuthData(): Promise<AuthDataType[]> {
    await this.deviceKeyInitializationPromise;
    if (!this.deviceKey) {
      console.error(
        "Device key not initialized. Cannot get all decrypted PIN auth data."
      );
      return [];
    }

    const allStoredRecords = await this.db.pins.toArray();
    if (!allStoredRecords || allStoredRecords.length === 0) return [];

    const decryptedRecords: AuthDataType[] = [];
    for (const storedRecord of allStoredRecords) {
      const decrypted = await this.decryptRecord(storedRecord);
      if (decrypted) {
        decryptedRecords.push(decrypted);
      }
    }
    return decryptedRecords;
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

  // Adds or updates user data with encrypted PIN
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

  // Updates user data with encrypted PIN
  async updatePinAuthData(data: AuthDataType[]): Promise<void> {
    return this.addPinAuthData(data);
  }

  // Retrieves all stored user data
  async clearPinAuthData(): Promise<void> {
    await this.db.pins.clear();
  }

  /**
   * Checks if a given PIN is unique among a list of existing AuthObjects.
   * This method is typically used on the server-side or in an admin context
   * before assigning a new PIN to ensure it's not already in use.
   * It does not interact with IndexedDB or use the deviceKey.
   * @param pin The PIN string to check for uniqueness.
   * @param existingAuthObjects An array of AuthObject items to check against.
   * @returns Promise<boolean> True if the PIN is unique, false otherwise.
   */
  async isPinUnique(
    pin: string,
    existingAuthObjects: AuthObject[]
  ): Promise<boolean> {
    if (!existingAuthObjects || existingAuthObjects.length === 0) {
      return true;
    }

    for (const authObject of existingAuthObjects) {
      if (!authObject || !authObject.h || !authObject.s) {
        console.warn("Skipping invalid AuthObject in isPinUnique check.");
        continue;
      }
      try {
        const keyFromSalt = await this.deriveKeyFromSalt(atob(authObject.s));
        const signatureToVerify = await crypto.subtle.sign(
          "HMAC",
          keyFromSalt,
          new TextEncoder().encode(pin)
        );
        const actualSignature = new Uint8Array(signatureToVerify);
        const expectedSignature = Uint8Array.from(atob(authObject.h), (c) =>
          c.charCodeAt(0)
        );

        if (
          actualSignature.length === expectedSignature.length &&
          actualSignature.every((val, i) => val === expectedSignature[i])
        ) {
          return false;
        }
      } catch (error) {
        console.error(
          "Error during isPinUnique check for an authObject:",
          error
        );
      }
    }
    return true;
  }
}
