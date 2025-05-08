import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import "fake-indexeddb/auto";

import { PinAuth, AuthDataType } from "../index";

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
});

describe("PinAuth Module", () => {
  it("should encrypt a PIN and produce h and s", () => {
    // This test relies on baseAuthData prepared in beforeAll
    expect(baseAuthData.auth.h).toBeTruthy();
    expect(baseAuthData.auth.s).toBeTruthy();
  });

  it("should store encrypted user data locally and verify it", async () => {
    await pinAuth.addPinAuthData([baseAuthData]);
    const verified = await pinAuth.verifyPin("1234");
    expect(verified).not.toBeNull();
    expect(verified?.id).toBe(testUserBase.id);
    expect(verified?.name).toBe(testUserBase.name);
    expect(verified?.role).toBe(testUserBase.role);
  });

  it("should return null for incorrect PIN after data is stored", async () => {
    // Add data first for this test's context
    await pinAuth.addPinAuthData([baseAuthData]);
    const verified = await pinAuth.verifyPin("wrong-pin");
    expect(verified).toBeNull();
  });

  it("should update stored data correctly", async () => {
    // 1. Add initial data
    await pinAuth.addPinAuthData([baseAuthData]);

    // 2. Prepare updated data (PIN and auth object remain the same, only other fields change)
    const updatedUserData = { ...baseAuthData, name: "Alice Updated" };
    await pinAuth.updatePinAuthData([updatedUserData]);

    // 3. Verify with the original PIN
    const result = await pinAuth.verifyPin("1234");
    expect(result).not.toBeNull();
    expect(result?.name).toBe("Alice Updated");
    expect(result?.id).toBe(testUserBase.id);
  });

  it("should clear stored data", async () => {
    // 1. Add some data
    await pinAuth.addPinAuthData([baseAuthData]);

    // 2. Clear the data
    await pinAuth.clearPinAuthData();

    // 3. Verify no data can be retrieved
    const result = await pinAuth.verifyPin("1234");
    expect(result).toBeNull();
  });
});

describe("Reinitialize PinAuth", () => {
  it("should reinitialize with new orgId and salt, causing old data to be unverifiable", async () => {
    const pinForReinitTest = "pin12345";

    // Stage 1:Add data with the initial configuration
    // pinAuth is initialized in beforeAll, and data is cleared in beforeEach
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

    // Stage 5: Assert orgId is updated (retained from the original test)
    // @ts-expect-error Property 'orgId' is private
    expect(pinAuth.orgId).toBe(newOrgId);

    // as it changes the outcome of cryptographic verification.
    verifiedUser = await pinAuth.verifyPin(pinForReinitTest);
    expect(verifiedUser).toBeNull();
  });
});

afterAll(async () => {
  // Final cleanup
  await pinAuth.clearPinAuthData();
});
