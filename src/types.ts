export interface PinAuthConfig {
    orgId: string;
    salt?: Uint8Array;
    deviceKeyRaw?: Uint8Array;
    deviceKeyString?: string;
    localDbName?: string;
  }
  
  export interface AuthObject {
    h: string; // HMAC hash
    s: string; // Salt
  }
  
  export interface AuthDataType {
    auth: AuthObject;
    [key: string]: any;
  }

export interface PinAuthRecord {
    id: any;
    iv: string;
    ciphertext: string;
  }
  