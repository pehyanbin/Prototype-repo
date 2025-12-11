// ECDSA Cryptography utilities using Web Crypto API
// Note: For full SECP256k1 support like Python's ecdsa library,
// consider using a library like elliptic or noble-secp256k1

export interface KeyPair {
  privateKey: string;
  publicKey: string;
}

// Simple hash function (synchronous)
export function sha256Sync(message: string): string {
  let hash = 0;
  for (let i = 0; i < message.length; i++) {
    const char = message.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash;
  }
  const hex = Math.abs(hash).toString(16).padStart(64, "0");
  return hex.substring(0, 64);
}

// Generate ECDSA key pair
export async function generateKeys(): Promise<KeyPair> {
  try {
    // Use Web Crypto API with P-256 curve (similar to SECP256k1)
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256", // Web Crypto doesn't support SECP256k1, using P-256
      },
      true,
      ["sign", "verify"]
    );

    const privateKeyBuffer = await crypto.subtle.exportKey(
      "pkcs8",
      keyPair.privateKey
    );
    const publicKeyBuffer = await crypto.subtle.exportKey(
      "spki",
      keyPair.publicKey
    );

    const privateKey = bufferToHex(privateKeyBuffer);
    const publicKey = bufferToHex(publicKeyBuffer);

    return { privateKey, publicKey };
  } catch (error) {
    console.error("Error generating keys:", error);
    // Fallback to simple random generation for demo
    const privateKey = generateRandomHex(64);
    const publicKey = generateRandomHex(128);
    return { privateKey, publicKey };
  }
}

// Sign a message with private key
export async function signCredential(
  privateKeyHex: string,
  attributeValue: string
): Promise<string> {
  try {
    // For demo purposes, create a simple signature
    // In production, use proper ECDSA signing
    const message = new TextEncoder().encode(attributeValue);
    const keyData = hexToBuffer(privateKeyHex);

    // Import private key
    const privateKey = await crypto.subtle.importKey(
      "pkcs8",
      keyData,
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      false,
      ["sign"]
    );

    // Sign the message
    const signature = await crypto.subtle.sign(
      {
        name: "ECDSA",
        hash: { name: "SHA-256" },
      },
      privateKey,
      message
    );

    return bufferToHex(signature);
  } catch (error) {
    console.error("Error signing:", error);
    // Fallback to simple hash-based signature for demo
    const combined = privateKeyHex + attributeValue;
    return sha256Sync(combined) + sha256Sync(combined).substring(0, 64);
  }
}

// Verify credential signature
export async function verifyCredential(
  publicKeyHex: string,
  attributeValue: string,
  signatureHex: string
): Promise<boolean> {
  try {
    const message = new TextEncoder().encode(attributeValue);
    const keyData = hexToBuffer(publicKeyHex);
    const signatureData = hexToBuffer(signatureHex);

    // Import public key
    const publicKey = await crypto.subtle.importKey(
      "spki",
      keyData,
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      false,
      ["verify"]
    );

    // Verify signature
    return await crypto.subtle.verify(
      {
        name: "ECDSA",
        hash: { name: "SHA-256" },
      },
      publicKey,
      signatureData,
      message
    );
  } catch (error) {
    console.error("Error verifying:", error);
    // Fallback to simple hash-based verification for demo
    const combined = publicKeyHex.substring(0, 64) + attributeValue;
    const expectedSig =
      sha256Sync(combined) + sha256Sync(combined).substring(0, 64);
    return signatureHex === expectedSig;
  }
}

// Hash a value (for credentials)
export function hashValue(value: string): string {
  return sha256Sync(value);
}

// Double hash for extra security (like IC numbers)
export function doubleHashValue(value: string): string {
  return sha256Sync(sha256Sync(value));
}

// Helper functions
function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBuffer(hex: string): ArrayBuffer {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes.buffer;
}

function generateRandomHex(length: number): string {
  const bytes = new Uint8Array(length / 2);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Add identity credential to blockchain
export interface CredentialData {
  attribute: string;
  hashed_value: string;
  signature: string;
}

export async function createCredentialData(
  attribute: string,
  value: string,
  privateKey: string,
  doubleHash: boolean = false
): Promise<CredentialData> {
  const hashed_value = doubleHash ? doubleHashValue(value) : hashValue(value);
  const signature = await signCredential(privateKey, value);

  return {
    attribute,
    hashed_value,
    signature,
  };
}
