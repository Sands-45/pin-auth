import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import "fake-indexeddb/auto";

import { PinAuth, AuthDataType, AuthObject } from "../index";

let pinAuth: PinAuth;
const deviceKeyString = "test-device-key";
const orgId = "org123";
const testDbName = "pinAuthTestDb";

// Base user data without auth, auth will be added after encryption
const testUserBase = {
  id: "user1",
  name: "Alice",
  role: "admin",
};

let baseAuthData: AuthDataType;

beforeAll(async () => {
  pinAuth = new PinAuth({ orgId, deviceKeyString, localDbName: testDbName });
  // Encrypt PIN once to get auth object structure
  const encryptedAuthPart = await pinAuth.encryptPin("1234");
  baseAuthData = { ...testUserBase, auth: encryptedAuthPart.auth };
});

beforeEach(async () => {
  // Clear data before each test to ensure isolation
  await pinAuth.clearPinAuthData();
  // Re-initialize pinAuth with a device key for tests that need it,
  // as clearPinAuthData doesn't affect the PinAuth instance's state itself.
  // This ensures deviceKey is available for add/get operations.
  pinAuth = new PinAuth({ orgId, deviceKeyString, localDbName: testDbName });
  const encryptedAuthPart = await pinAuth.encryptPin("1234");
  baseAuthData = { ...testUserBase, auth: encryptedAuthPart.auth };
});

describe("PinAuth Module", () => {
  it("should encrypt a PIN and produce h and s", () => {
    // This test relies on baseAuthData prepared in beforeAll
    expect(baseAuthData.auth.h).toBeTruthy();
    expect(baseAuthData.auth.s).toBeTruthy();
  });

  it("should store encrypted user data locally and verify it", async () => {
    await pinAuth.addPinAuthData([baseAuthData]);
    // verifyPin now only takes the pin
    const verifiedUser = await pinAuth.verifyPin("1234");
    expect(verifiedUser).not.toBeNull();
    if (verifiedUser) {
      expect(verifiedUser.id).toBe(testUserBase.id);
      expect(verifiedUser.name).toBe(testUserBase.name);
      expect(verifiedUser.role).toBe(testUserBase.role);
      expect(verifiedUser).not.toHaveProperty("auth");
    }
  });

  it("should return null for incorrect PIN after data is stored", async () => {
    await pinAuth.addPinAuthData([baseAuthData]);
    // verifyPin now only takes the pin
    const verified = await pinAuth.verifyPin("wrong-pin");
    expect(verified).toBeNull();
  });

  it("should update stored data correctly", async () => {
    await pinAuth.addPinAuthData([baseAuthData]);

    const updatedUserDataPayload = {
      ...testUserBase,
      name: "Alice Updated",
      auth: baseAuthData.auth,
    };
    await pinAuth.updatePinAuthData([updatedUserDataPayload]);

    // Verify with the original PIN
    const result = await pinAuth.verifyPin("1234");
    expect(result).not.toBeNull();
    if (result) {
      expect(result.name).toBe("Alice Updated");
      expect(result.id).toBe(testUserBase.id);
    }
  });

  it("should clear stored data, and verifyPin should return null", async () => {
    await pinAuth.addPinAuthData([baseAuthData]);
    await pinAuth.clearPinAuthData();
    // After clearing, verifyPin should not find any data
    const result = await pinAuth.verifyPin("1234");
    expect(result).toBeNull();
  });

  describe("Data Retrieval Methods", () => {
    it("getDecryptedPinAuthDataById should return null if device key is not set", async () => {
      const pinAuthNoDeviceKey = new PinAuth({
        orgId,
        localDbName: `${testDbName}_noKey`,
      });
      // Add data using an instance that has a device key to simulate data being present
      await pinAuth.addPinAuthData([baseAuthData]);
      const data = await pinAuthNoDeviceKey.getDecryptedPinAuthDataById(
        testUserBase.id
      );
      expect(data).toBeNull();
    });

    it("getDecryptedPinAuthDataById should retrieve and decrypt correct data", async () => {
      await pinAuth.addPinAuthData([baseAuthData]);
      const data = await pinAuth.getDecryptedPinAuthDataById(testUserBase.id);
      expect(data).not.toBeNull();
      expect(data?.id).toBe(testUserBase.id);
      expect(data?.name).toBe(testUserBase.name);
      expect(data?.auth.h).toBe(baseAuthData.auth.h);
    });

    it("getDecryptedPinAuthDataById should return null for non-existent ID", async () => {
      const data = await pinAuth.getDecryptedPinAuthDataById("non-existent-id");
      expect(data).toBeNull();
    });

    it("getAllDecryptedPinAuthData should retrieve all decrypted data", async () => {
      const user2Base = { id: "user2", name: "Bob" };
      const encryptedAuthPart2 = await pinAuth.encryptPin("5678");
      const user2AuthData = { ...user2Base, auth: encryptedAuthPart2.auth };
      await pinAuth.addPinAuthData([baseAuthData, user2AuthData]);

      const allData = await pinAuth.getAllDecryptedPinAuthData();
      expect(allData.length).toBe(2);
      expect(allData.find((u) => u.id === "user1")?.name).toBe("Alice");
      expect(allData.find((u) => u.id === "user2")?.name).toBe("Bob");
    });

    it("getAllDecryptedPinAuthData should return empty array if no data", async () => {
      const allData = await pinAuth.getAllDecryptedPinAuthData();
      expect(allData.length).toBe(0);
    });

    it("getAllDecryptedPinAuthData should return empty array if device key is not set", async () => {
      const pinAuthNoDeviceKey = new PinAuth({
        orgId,
        localDbName: `${testDbName}_noKey_all`,
      });
      await pinAuth.addPinAuthData([baseAuthData]);
      const allData = await pinAuthNoDeviceKey.getAllDecryptedPinAuthData();
      expect(allData.length).toBe(0);
    });
  });
});

describe("Reinitialize PinAuth", () => {
  it("should reinitialize with new orgId and salt, causing old data to be unverifiable", async () => {
    const pinForReinitTest = "pin12345";

    // Stage 1: Add data with the initial configuration
    const initialEncryptedAuth = await pinAuth.encryptPin(pinForReinitTest);
    const testData = {
      ...testUserBase,
      id: "reinitTestUser",
      auth: initialEncryptedAuth.auth,
    };
    await pinAuth.addPinAuthData([testData]);

    // Stage 2: Verify the PIN works with the initial configuration
    let verifiedUser = await pinAuth.verifyPin(pinForReinitTest);
    expect(verifiedUser).not.toBeNull();
    expect(verifiedUser?.id).toBe(testData.id);

    // Stage 3: Define new configuration parameters
    const newOrgId = "new-org";
    const newSalt = new Uint8Array(16);
    crypto.getRandomValues(newSalt);

    // Stage 4: Update PinAuth configuration
    await pinAuth.reinitializePinAuth({ orgId: newOrgId, salt: newSalt });

    // Stage 5: Assert orgId is updated
    // @ts-expect-error Property 'orgId' is private
    expect(pinAuth.orgId).toBe(newOrgId);

    // Data was cleared during reinitializePinAuth, so verifyPin should return null for the old PIN
    verifiedUser = await pinAuth.verifyPin(pinForReinitTest);
    expect(verifiedUser).toBeNull();

    // Stage 6: Add new data with the new configuration and verify it
    const newPinAuthData = await pinAuth.encryptPin(pinForReinitTest);
    const newTestData = {
      ...testUserBase,
      id: "reinitTestUserNew",
      auth: newPinAuthData.auth,
    };
    await pinAuth.addPinAuthData([newTestData]);
    verifiedUser = await pinAuth.verifyPin(pinForReinitTest);
    expect(verifiedUser).not.toBeNull();
    expect(verifiedUser?.id).toBe(newTestData.id);
  });
});

describe("isPinUnique Method", () => {
  let authObjects: AuthObject[];
  const pin1 = "1111";
  const pin2 = "2222"; 
  // Unique PIN
  const pin3 = "3333";

  beforeAll(async () => {
    // Create a separate PinAuth instance for generating auth objects if needed,
    // or use the existing one. Ensure orgId is consistent.
    const tempPinAuth = new PinAuth({ orgId });
    const auth1 = await tempPinAuth.encryptPin(pin1);
    const auth2 = await tempPinAuth.encryptPin(pin2);
    authObjects = [auth1.auth, auth2.auth];
  });

  it("should return false if PIN exists in the provided authObjects", async () => {
    const isUnique = await pinAuth.isPinUnique(pin1, authObjects);
    expect(isUnique).toBe(false);
  });

  it("should return true if PIN does not exist in the provided authObjects", async () => {
    const isUnique = await pinAuth.isPinUnique(pin3, authObjects);
    expect(isUnique).toBe(true);
  });

  it("should return true for an empty list of authObjects", async () => {
    const isUnique = await pinAuth.isPinUnique(pin1, []);
    expect(isUnique).toBe(true);
  });

  it("should handle authObjects with different salts correctly", async () => {
    // Create auth objects with potentially different salts (encryptPin uses instance salt)
    const pAuth1 = new PinAuth({ orgId: "testOrg" });
    const ao1 = (await pAuth1.encryptPin("0000")).auth;

    const pAuth2Salt = crypto.getRandomValues(new Uint8Array(16));
    const pAuth2 = new PinAuth({ orgId: "testOrg", salt: pAuth2Salt });
    const ao2 = (await pAuth2.encryptPin("9999")).auth;

    const customAuthObjects = [ao1, ao2];

    // Check against pin "0000" which matches ao1
    let isUnique = await pAuth1.isPinUnique("0000", customAuthObjects);
    expect(isUnique).toBe(false);
    // Check against pin "9999" which matches ao2
    isUnique = await pAuth1.isPinUnique("9999", customAuthObjects);
    expect(isUnique).toBe(false);
    // Check against a new pin "5555"
    isUnique = await pAuth1.isPinUnique("5555", customAuthObjects);
    expect(isUnique).toBe(true);
  });
});

afterAll(async () => {
  // Final cleanup
  await pinAuth.clearPinAuthData();
});
