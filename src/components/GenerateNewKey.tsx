import React, { useState, useEffect, useRef } from "react";
import Prism from "prismjs";
import "prismjs/components/prism-json";
import "prismjs/themes/prism.css";

// Types
interface KeyAlgorithm {
  value: string;
  label: string;
  keyType: string;
  description?: string;
}

interface Curve {
  value: string;
  label: string;
  algorithm: string;
}

// Constants
const KEY_TYPES = {
  RSA: "RSA",
  ECDSA: "ECDSA",
  ED25519: "Ed25519",
  X25519: "X25519",
  AES: "AES",
  OCT: "OCT", // Octet sequence (for symmetric keys)
  HMAC: "HMAC" // For HMAC-based signatures
} as const;

const RSA_SIGNATURE_ALGORITHMS: KeyAlgorithm[] = [
  { value: "RS256", label: "RS256 (RSA + SHA-256)", keyType: KEY_TYPES.RSA },
  { value: "RS384", label: "RS384 (RSA + SHA-384)", keyType: KEY_TYPES.RSA },
  { value: "RS512", label: "RS512 (RSA + SHA-512)", keyType: KEY_TYPES.RSA },
  { value: "PS256", label: "PS256 (RSA-PSS + SHA-256)", keyType: KEY_TYPES.RSA, description: "RSA-PSS using SHA-256 and MGF1 with SHA-256" },
  { value: "PS384", label: "PS384 (RSA-PSS + SHA-384)", keyType: KEY_TYPES.RSA, description: "RSA-PSS using SHA-384 and MGF1 with SHA-384" },
  { value: "PS512", label: "PS512 (RSA-PSS + SHA-512)", keyType: KEY_TYPES.RSA, description: "RSA-PSS using SHA-512 and MGF1 with SHA-512" },
];

const HMAC_ALGORITHMS: KeyAlgorithm[] = [
  { value: "HS256", label: "HS256 (HMAC + SHA-256)", keyType: KEY_TYPES.HMAC, description: "HMAC using SHA-256" },
  { value: "HS384", label: "HS384 (HMAC + SHA-384)", keyType: KEY_TYPES.HMAC, description: "HMAC using SHA-384" },
  { value: "HS512", label: "HS512 (HMAC + SHA-512)", keyType: KEY_TYPES.HMAC, description: "HMAC using SHA-512" },
];

const NONE_ALGORITHMS: KeyAlgorithm[] = [
  { value: "none", label: "none (Unsecured JWS)", keyType: KEY_TYPES.OCT, description: "Unsecured JWS (no signature)" },
];

const RSA_ENCRYPTION_ALGORITHMS: KeyAlgorithm[] = [
  { value: "RSA-OAEP", label: "RSA-OAEP (RSAES OAEP using default parameters)", keyType: KEY_TYPES.RSA, description: "RSAES OAEP using SHA-1 and MGF1 with SHA-1" },
  { value: "RSA-OAEP-256", label: "RSA-OAEP-256 (RSAES OAEP using SHA-256 and MGF1 with SHA-256)", keyType: KEY_TYPES.RSA, description: "RSAES OAEP using SHA-256 and MGF1 with SHA-256" },
  { value: "RSA1_5", label: "RSA1_5 (RSAES-PKCS1-v1_5)", keyType: KEY_TYPES.RSA, description: "RSAES-PKCS1-v1_5 - DEPRECATED: Not recommended for new applications" },
];

const ECDSA_ALGORITHMS: KeyAlgorithm[] = [
  { value: "ES256", label: "ES256 (ECDSA + SHA-256)", keyType: KEY_TYPES.ECDSA },
  { value: "ES384", label: "ES384 (ECDSA + SHA-384)", keyType: KEY_TYPES.ECDSA },
  { value: "ES512", label: "ES512 (ECDSA + SHA-512)", keyType: KEY_TYPES.ECDSA },
];

const ED25519_ALGORITHMS: KeyAlgorithm[] = [
  { value: "EdDSA", label: "EdDSA (Ed25519)", keyType: KEY_TYPES.ED25519 },
];

const ECDH_ALGORITHMS: KeyAlgorithm[] = [
  { value: "ECDH-ES", label: "ECDH-ES (Elliptic Curve Diffie-Hellman Ephemeral Static)", keyType: KEY_TYPES.X25519, description: "Direct key agreement" },
  { value: "ECDH-ES+A128KW", label: "ECDH-ES+A128KW (ECDH-ES with A128KW wrapping)", keyType: KEY_TYPES.X25519, description: "ECDH-ES using Concat KDF and CEK wrapped with A128KW" },
  { value: "ECDH-ES+A256KW", label: "ECDH-ES+A256KW (ECDH-ES with A256KW wrapping)", keyType: KEY_TYPES.X25519, description: "ECDH-ES using Concat KDF and CEK wrapped with A256KW" },
  { value: "ECDH-ES+A128GCMKW", label: "ECDH-ES+A128GCMKW (ECDH-ES with A128GCMKW wrapping)", keyType: KEY_TYPES.X25519, description: "ECDH-ES using Concat KDF and CEK wrapped with A128GCMKW" },
  { value: "ECDH-ES+A256GCMKW", label: "ECDH-ES+A256GCMKW (ECDH-ES with A256GCMKW wrapping)", keyType: KEY_TYPES.X25519, description: "ECDH-ES using Concat KDF and CEK wrapped with A256GCMKW" },
];

const AES_KEY_WRAP_ALGORITHMS: KeyAlgorithm[] = [
  { value: "A128KW", label: "A128KW (AES Key Wrap with 128-bit key)", keyType: KEY_TYPES.AES, description: "AES Key Wrap with 128-bit key" },
  { value: "A256KW", label: "A256KW (AES Key Wrap with 256-bit key)", keyType: KEY_TYPES.AES, description: "AES Key Wrap with 256-bit key" },
  { value: "A128GCMKW", label: "A128GCMKW (AES GCM Key Wrap with 128-bit key)", keyType: KEY_TYPES.AES, description: "AES GCM Key Wrap with 128-bit key" },
  { value: "A256GCMKW", label: "A256GCMKW (AES GCM Key Wrap with 256-bit key)", keyType: KEY_TYPES.AES, description: "AES GCM Key Wrap with 256-bit key" },
];

const PBES2_ALGORITHMS: KeyAlgorithm[] = [
  { value: "PBES2-HS256+A128KW", label: "PBES2-HS256+A128KW (PBES2 with HMAC SHA-256 and A128KW)", keyType: KEY_TYPES.OCT, description: "PBES2 with HMAC SHA-256 and A128KW wrapping" },
  { value: "PBES2-HS512+A256KW", label: "PBES2-HS512+A256KW (PBES2 with HMAC SHA-512 and A256KW)", keyType: KEY_TYPES.OCT, description: "PBES2 with HMAC SHA-512 and A256KW wrapping" },
];

const DIRECT_ALGORITHMS: KeyAlgorithm[] = [
  { value: "dir", label: "dir (Direct use of a shared symmetric key)", keyType: KEY_TYPES.OCT, description: "Direct use of a shared symmetric key" },
];



const ECDSA_CURVES: Curve[] = [
  { value: "P-256", label: "P-256 (secp256r1)", algorithm: "ES256" },
  { value: "P-384", label: "P-384 (secp384r1)", algorithm: "ES384" },
  { value: "P-521", label: "P-521 (secp521r1)", algorithm: "ES512" },
];

const RSA_KEY_SIZES = [
  { value: 1024, label: "1024 bits" },
  { value: 2048, label: "2048 bits (recommended)" },
  { value: 4096, label: "4096 bits" },
];

const AES_KEY_SIZES = [
  { value: 128, label: "128 bits" },
  { value: 256, label: "256 bits (recommended)" },
];

// Utility functions
const arrayBufferToBase64 = (buffer: ArrayBuffer): string => {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i] || 0);
  }
  return btoa(binary);
};

const generateFingerprint = async (publicKey: CryptoKey): Promise<string> => {
  const exported = await crypto.subtle.exportKey("spki", publicKey);
  const hash = await crypto.subtle.digest("SHA-256", exported);
  const hashArray = new Uint8Array(hash);
  // Convert to base64 format like SSH-keygen SHA256 fingerprint
  const base64 = btoa(String.fromCharCode(...hashArray));
  return base64;
};

const cryptoKeyToJWK = async (
  cryptoKey: CryptoKey, 
  keyId: string, 
  alg: string, 
  use: string
): Promise<string> => {
  const jwk = await crypto.subtle.exportKey("jwk", cryptoKey);
  
  (jwk as any).kid = keyId;
  (jwk as any).alg = alg;
  (jwk as any).use = use;
  
  return JSON.stringify(jwk, null, 2);
};

const cryptoKeyToPEM = async (cryptoKey: CryptoKey, isPrivate: boolean): Promise<string> => {
  const format = isPrivate ? "pkcs8" : "spki";
  const exported = await crypto.subtle.exportKey(format, cryptoKey);
  const base64 = arrayBufferToBase64(exported);
  
  const header = isPrivate ? "-----BEGIN PRIVATE KEY-----" : "-----BEGIN PUBLIC KEY-----";
  const footer = isPrivate ? "-----END PRIVATE KEY-----" : "-----END PUBLIC KEY-----";
  
  const lines = [];
  for (let i = 0; i < base64.length; i += 64) {
    lines.push(base64.slice(i, i + 64));
  }
  
  return `${header}\n${lines.join('\n')}\n${footer}`;
};

// Key generation functions
const generateRSAKey = async (
  keyUse: string,
  keyAlgorithm: string,
  keySize: number,
  keyOperations: string[]
): Promise<CryptoKeyPair> => {
  let algorithm: string;
  let hashAlgorithm: string;
  
  if (keyUse === "sig") {
    // For signatures, determine algorithm based on the selected algorithm
    if (keyAlgorithm.startsWith("PS")) {
      // RSA-PSS algorithms
      algorithm = "RSA-PSS";
      hashAlgorithm = keyAlgorithm === "PS256" ? "SHA-256" : 
                     keyAlgorithm === "PS384" ? "SHA-384" : 
                     keyAlgorithm === "PS512" ? "SHA-512" : "SHA-256";
    } else {
      // RSA-PKCS1-v1_5 algorithms
      algorithm = "RSASSA-PKCS1-v1_5";
      hashAlgorithm = keyAlgorithm === "RS256" ? "SHA-256" : 
                     keyAlgorithm === "RS384" ? "SHA-384" : 
                     keyAlgorithm === "RS512" ? "SHA-512" : "SHA-256";
    }
  } else {
    // For encryption, always use RSA-OAEP for key generation
    // The specific algorithm (RSA1_5, RSA-OAEP, RSA-OAEP-256) is used during encryption/decrypt
    algorithm = "RSA-OAEP";
    hashAlgorithm = "SHA-1"; // Default hash for key generation
  }
  
  const keyUsages: KeyUsage[] = keyOperations.length === 0
    ? (keyUse === "sig" ? ["sign", "verify"] : ["encrypt", "decrypt"])
    : keyOperations as KeyUsage[];
  
  return await crypto.subtle.generateKey(
    {
      name: algorithm,
      modulusLength: keySize,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: hashAlgorithm,
    } as RsaHashedKeyGenParams,
    true,
    keyUsages
  );
};

const generateECDSAKey = async (
  curve: string,
  keyOperations: string[]
): Promise<CryptoKeyPair> => {
  const keyUsages: KeyUsage[] = keyOperations.length === 0
    ? ["sign", "verify"]
    : keyOperations as KeyUsage[];
  
  return await crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: curve,
    } as EcKeyGenParams,
    true,
    keyUsages
  );
};

const generateEd25519Key = async (keyOperations: string[]): Promise<CryptoKeyPair> => {
  const keyUsages: KeyUsage[] = keyOperations.length === 0
    ? ["sign", "verify"]
    : keyOperations as KeyUsage[];
  
  return await crypto.subtle.generateKey(
    {
      name: "Ed25519",
    } as any,
    true,
    keyUsages
  );
};

const generateX25519Key = async (keyOperations: string[]): Promise<CryptoKeyPair> => {
  const keyUsages: KeyUsage[] = keyOperations.length === 0
    ? ["deriveKey", "deriveBits"]
    : keyOperations as KeyUsage[];
  
  // Note: X25519 is not directly supported in Web Crypto API
  // We'll use P-256 for ECDH which provides similar functionality
  return await crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256",
    } as EcKeyGenParams,
    true,
    keyUsages
  );
};

const generateAESKey = async (
  keySize: number,
  keyOperations: string[]
): Promise<CryptoKey> => {
  const keyUsages: KeyUsage[] = keyOperations.length === 0
    ? ["wrapKey", "unwrapKey", "encrypt", "decrypt"]
    : keyOperations as KeyUsage[];
  
  return await crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: keySize,
    } as AesKeyGenParams,
    true,
    keyUsages
  );
};

const generateOctKey = async (
  keySize: number,
  keyOperations: string[]
): Promise<CryptoKey> => {
  const keyUsages: KeyUsage[] = keyOperations.length === 0
    ? ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
    : keyOperations as KeyUsage[];
  
  // For OCT keys, we generate a random octet sequence
  const keyData = crypto.getRandomValues(new Uint8Array(keySize / 8));
  
  return await crypto.subtle.importKey(
    "raw",
    keyData,
    {
      name: "AES-GCM",
    },
    true, // Changed from false to true to make the key extractable
    keyUsages
  );
};

const generateHMACKey = async (
  keyAlgorithm: string,
  keySize: number,
  keyOperations: string[]
): Promise<CryptoKey> => {
  let hashAlgorithm: string;
  
  // Determine hash algorithm based on the HMAC algorithm
  hashAlgorithm = keyAlgorithm === "HS256" ? "SHA-256" : 
                 keyAlgorithm === "HS384" ? "SHA-384" : 
                 keyAlgorithm === "HS512" ? "SHA-512" : "SHA-256";
  
  const keyUsages: KeyUsage[] = keyOperations.length === 0
    ? ["sign", "verify"]
    : keyOperations as KeyUsage[];
  
  return await crypto.subtle.generateKey(
    {
      name: "HMAC",
      hash: hashAlgorithm,
      length: keySize,
    } as HmacKeyGenParams,
    true,
    keyUsages
  );
};

// Styles
const styles = {
  input: {
    width: "100%",
    padding: "8px 12px",
    borderRadius: "4px",
    border: "1px solid #dee2e6",
    fontSize: "14px",
    fontFamily: "Inter, sans-serif",
    outline: "none",
    transition: "border-color 0.2s",
    boxSizing: "border-box" as const,
    color: "#495057",
    backgroundColor: "#fff"
  },
  label: {
    fontWeight: 600,
    color: "#495057",
    fontSize: "14px",
    marginBottom: "6px",
    display: "block" as const,
    fontFamily: "Inter, sans-serif"
  },
  button: {
    background: "rgb(11, 99, 233)",
    color: "#fff",
    border: "none",
    borderRadius: 4,
    padding: "10px 20px",
    fontWeight: 600,
    fontSize: 14,
    cursor: "pointer",
    fontFamily: "Inter, sans-serif",
    transition: "background-color 0.2s"
  },
  buttonDisabled: {
    background: "#6c757d",
    cursor: "not-allowed"
  },
  error: {
    color: "#721c24",
    marginTop: 16,
    padding: "12px",
    background: "#f8d7da",
    border: "1px solid #f5c6cb",
    borderRadius: 4,
    fontSize: 14,
    fontFamily: "Inter, sans-serif"
  },
  info: {
    marginBottom: 20,
    padding: "12px",
    backgroundColor: "#e3f2fd",
    border: "1px solid #2196f3",
    borderRadius: "4px",
    fontSize: "14px",
    color: "#1976d2"
  },
  output: {
    background: "#f8f9fa",
    padding: 16,
    borderRadius: 4,
    fontSize: 14,
    marginTop: 6,
    border: "1px solid #e9ecef",
    fontFamily: "monospace",
    lineHeight: 1.5,
    color: "#495057",
    minHeight: "120px",
    whiteSpace: "pre-wrap" as const,
    wordBreak: "break-all" as const,
    textAlign: "left" as const,
    overflow: "auto"
  }
};

// Sub-components
const KeyUseSelector: React.FC<{
  value: string;
  onChange: (value: string) => void;
}> = ({ value, onChange }) => (
  <div style={{ marginBottom: 16 }}>
    <label style={styles.label}>Key Use</label>
    <div style={{ 
      display: "flex", 
      gap: 16,
      padding: "12px",
      border: "1px solid #e9ecef",
      borderRadius: "4px",
      backgroundColor: "#f8f9fa"
    }}>
      <label style={{ 
        display: "flex", 
        alignItems: "center", 
        gap: 8,
        cursor: "pointer",
        padding: "8px 12px",
        borderRadius: "4px",
        backgroundColor: value === "sig" ? "#e3f2fd" : "transparent",
        transition: "background-color 0.2s"
      }}>
        <input
          type="radio"
          name="keyUse"
          value="sig"
          checked={value === "sig"}
          onChange={(e) => onChange(e.target.value)}
          style={{ 
            width: "16px", 
            height: "16px",
            cursor: "pointer"
          }}
        />
        <div>
          <div style={{ fontWeight: 500, fontSize: "14px" }}>Signature</div>
          <div style={{ fontSize: "12px", color: "#6c757d" }}>For creating and verifying digital signatures</div>
        </div>
      </label>
      <label style={{ 
        display: "flex", 
        alignItems: "center", 
        gap: 8,
        cursor: "pointer",
        padding: "8px 12px",
        borderRadius: "4px",
        backgroundColor: value === "enc" ? "#e3f2fd" : "transparent",
        transition: "background-color 0.2s"
      }}>
        <input
          type="radio"
          name="keyUse"
          value="enc"
          checked={value === "enc"}
          onChange={(e) => onChange(e.target.value)}
          style={{ 
            width: "16px", 
            height: "16px",
            cursor: "pointer"
          }}
        />
        <div>
          <div style={{ fontWeight: 500, fontSize: "14px" }}>Encryption</div>
          <div style={{ fontSize: "12px", color: "#6c757d" }}>For encrypting and decrypting data</div>
        </div>
      </label>
    </div>
  </div>
);

const KeyTypeSelector: React.FC<{
  value: string;
  onChange: (value: string) => void;
  keyUse: string;
}> = ({ value, onChange, keyUse }) => {
  const getAvailableKeyTypes = () => {
    if (keyUse === "sig") {
      return [
        { value: KEY_TYPES.RSA, label: "RSA - Digital signatures (most versatile)", description: "Supports multiple signature algorithms" },
        { value: KEY_TYPES.ECDSA, label: "ECDSA - Digital signatures (faster, smaller keys)", description: "Elliptic curve digital signatures" },
        { value: KEY_TYPES.ED25519, label: "Ed25519 - Modern digital signatures", description: "Very fast, very secure signatures" },
        { value: KEY_TYPES.HMAC, label: "HMAC - Symmetric signatures", description: "Hash-based Message Authentication Code" }
      ];
    } else {
      return [
        { value: KEY_TYPES.RSA, label: "RSA - Encryption (most versatile)", description: "Supports multiple encryption algorithms" },
        { value: KEY_TYPES.X25519, label: "X25519 - Key exchange and encryption", description: "Elliptic curve key exchange (ECDH)" },
        { value: KEY_TYPES.AES, label: "AES - Symmetric encryption", description: "Advanced Encryption Standard for symmetric encryption" },
        { value: KEY_TYPES.OCT, label: "OCT - Octet sequence", description: "Raw octet sequence for symmetric keys" }
      ];
    }
  };

  return (
    <div style={{ marginBottom: 16 }}>
      <label style={styles.label}>Key Type</label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={styles.input}
      >
        {getAvailableKeyTypes().map(type => (
          <option key={type.value} value={type.value}>{type.label}</option>
        ))}
      </select>
      {getAvailableKeyTypes().find(t => t.value === value)?.description && (
        <div style={{ 
          marginTop: 4, 
          fontSize: "12px", 
          color: "#6c757d",
          fontStyle: "italic"
        }}>
          {getAvailableKeyTypes().find(t => t.value === value)?.description}
        </div>
      )}
    </div>
  );
};

const KeyAlgorithmSelector: React.FC<{
  value: string;
  onChange: (value: string) => void;
  keyType: string;
  keyUse: string;
}> = ({ value, onChange, keyType, keyUse }) => {
  const getAvailableAlgorithms = () => {
    if (keyUse === "sig") {
      switch (keyType) {
        case KEY_TYPES.RSA: return RSA_SIGNATURE_ALGORITHMS;
        case KEY_TYPES.ECDSA: return ECDSA_ALGORITHMS;
        case KEY_TYPES.ED25519: return ED25519_ALGORITHMS;
        case KEY_TYPES.HMAC: return [...HMAC_ALGORITHMS, ...NONE_ALGORITHMS];
        default: return RSA_SIGNATURE_ALGORITHMS;
      }
    } else {
      switch (keyType) {
        case KEY_TYPES.RSA: return RSA_ENCRYPTION_ALGORITHMS;
        case KEY_TYPES.X25519: return ECDH_ALGORITHMS;
        case KEY_TYPES.AES: return AES_KEY_WRAP_ALGORITHMS;
        case KEY_TYPES.OCT: return [...PBES2_ALGORITHMS, ...DIRECT_ALGORITHMS];
        default: return RSA_ENCRYPTION_ALGORITHMS;
      }
    }
  };

  return (
    <div style={{ marginBottom: 16 }}>
      <label style={styles.label}>Key Algorithm</label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={styles.input}
      >
        {getAvailableAlgorithms().map(alg => (
          <option key={alg.value} value={alg.value}>{alg.label}</option>
        ))}
      </select>
    </div>
  );
};

const KeySizeSelector: React.FC<{
  value: number;
  onChange: (value: number) => void;
  keyType: string;
}> = ({ value, onChange, keyType }) => {
  const getKeySizes = () => {
    if (keyType === KEY_TYPES.AES || keyType === KEY_TYPES.OCT || keyType === KEY_TYPES.HMAC) {
      return AES_KEY_SIZES;
    }
    return RSA_KEY_SIZES;
  };

  return (
    <div style={{ marginBottom: 16 }}>
      <label style={styles.label}>Key Size (bits)</label>
      <select
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        style={styles.input}
      >
        {getKeySizes().map((size: { value: number; label: string }) => (
          <option key={size.value} value={size.value}>{size.label}</option>
        ))}
      </select>

    </div>
  );
};

const CurveSelector: React.FC<{
  value: string;
  onChange: (value: string) => void;
}> = ({ value, onChange }) => (
  <div style={{ marginBottom: 16 }}>
    <label style={styles.label}>Curve</label>
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      style={styles.input}
    >
      {ECDSA_CURVES.map(curve => (
        <option key={curve.value} value={curve.value}>{curve.label}</option>
      ))}
    </select>
  </div>
);

const KeyIdSelector: React.FC<{
  value: string;
  onChange: (value: string) => void;
}> = ({ value, onChange }) => (
  <div style={{ marginBottom: 16 }}>
    <label style={styles.label}>Key ID (kid)</label>
    <input
      type="text"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      style={styles.input}
      placeholder="Leave empty to use fingerprint"
    />
    <div style={{ 
      marginTop: 4, 
      fontSize: "12px", 
      color: "#6c757d",
      fontStyle: "italic"
    }}>
      A unique identifier for this key. If left empty, a SHA256 fingerprint will be generated automatically.
    </div>
  </div>
);

const Ed25519Info: React.FC = () => (
  <div style={styles.info}>
    <strong>Ed25519:</strong> Uses the Ed25519 curve (Edwards curve over Fp with p = 2^255 - 19). 
    Provides 128-bit security level with very fast signature generation and verification.
  </div>
);

const X25519Info: React.FC = () => (
  <div style={styles.info}>
    <strong>X25519:</strong> Uses the X25519 curve for Elliptic Curve Diffie-Hellman (ECDH) key exchange. 
    Provides 128-bit security level and is commonly used for key agreement protocols like TLS 1.3.
  </div>
);

const RSA1_5Warning: React.FC = () => (
  <div style={{
    marginBottom: 16,
    padding: "12px",
    backgroundColor: "#fff3cd",
    border: "1px solid #ffeaa7",
    borderRadius: "4px",
    fontSize: "14px",
    color: "#856404"
  }}>
    <strong>⚠️ Security Warning:</strong> RSA1_5 (RSAES-PKCS1-v1_5) is deprecated and not recommended for new applications. 
    It's vulnerable to padding oracle attacks. Consider using RSA-OAEP or RSA-OAEP-256 instead for better security.
  </div>
);

const NoneAlgorithmInfo: React.FC = () => (
  <div style={{
    marginBottom: 16,
    padding: "12px",
    backgroundColor: "#fff3cd",
    border: "1px solid #ffeaa7",
    borderRadius: "4px",
    fontSize: "14px",
    color: "#856404"
  }}>
    <strong>⚠️ Security Warning:</strong> The "none" algorithm creates an unsecured JWS with no signature. 
    This should only be used for testing or when the JWS payload is not sensitive. Never use this in production for sensitive data.
  </div>
);



const ResultsSection: React.FC<{
  generatedJWK: string;
  generatedPublicKey: string;
  generatedPrivateKey: string;
  highlightedJWK: string;
  jwkPreRef: React.RefObject<HTMLPreElement>;
  onCopyJWK: () => Promise<void>;
  onCopyPublicKey: () => Promise<void>;
  onCopyPrivateKey: () => Promise<void>;
  copySuccess: { jwk: boolean; publicKey: boolean; privateKey: boolean };
  generatedPublicJWK?: string;
  highlightedPublicJWK?: string;
  onCopyPublicJWK?: () => Promise<void>;
  copySuccessPublicJWK?: boolean;
  showPublicJWK?: boolean;
  keyType: string;
}> = ({ 
  generatedJWK,
  generatedPublicKey, 
  generatedPrivateKey,
  highlightedJWK, 
  jwkPreRef,
  onCopyJWK,
  onCopyPublicKey,
  onCopyPrivateKey,
  copySuccess,
  generatedPublicJWK,
  highlightedPublicJWK,
  onCopyPublicJWK,
  copySuccessPublicJWK,
  showPublicJWK,
  keyType
}) => {
  const isSymmetric = keyType === 'AES' || keyType === 'OCT' || keyType === 'HMAC';
  return (
    <div style={{ marginTop: 24 }}>
      {showPublicJWK && !isSymmetric && (
        <div style={{ marginBottom: 20 }}>
          <label style={styles.label}>JWK Public Key</label>
          <div style={{ position: "relative" }}>
            <pre 
              style={styles.output}
              dangerouslySetInnerHTML={{
                __html: highlightedPublicJWK || '<span style="color: #6c757d; font-style: italic;">No JWK generated yet</span>'
              }}
            />
            {generatedPublicJWK && (
              <button
                onClick={onCopyPublicJWK}
                style={{
                  position: "absolute",
                  top: "10px",
                  right: "10px",
                  background: copySuccessPublicJWK ? "#28a745" : "#6c757d",
                  color: "#fff",
                  border: "none",
                  borderRadius: "4px",
                  padding: "4px 8px",
                  fontSize: "12px",
                  fontWeight: 500,
                  cursor: "pointer",
                  fontFamily: "Inter, sans-serif",
                  transition: "background-color 0.2s",
                  zIndex: 10
                }}
              >
                {copySuccessPublicJWK ? "COPIED!" : "COPY"}
              </button>
            )}
          </div>
        </div>
      )}
      <div style={{ marginBottom: 20 }}>
        <label style={styles.label}>{isSymmetric ? 'JWK Key' : 'JWK Private Key'}</label>
        <div style={{ position: "relative" }}>
          <pre 
            ref={jwkPreRef}
            style={styles.output}
            dangerouslySetInnerHTML={{
              __html: highlightedJWK || '<span style="color: #6c757d; font-style: italic;">No JWK generated yet</span>'
            }}
          />
          {generatedJWK && (
            <button
              onClick={onCopyJWK}
              style={{
                position: "absolute",
                top: "10px",
                right: "10px",
                background: copySuccess.jwk ? "#28a745" : "#6c757d",
                color: "#fff",
                border: "none",
                borderRadius: "4px",
                padding: "4px 8px",
                fontSize: "12px",
                fontWeight: 500,
                cursor: "pointer",
                fontFamily: "Inter, sans-serif",
                transition: "background-color 0.2s",
                zIndex: 10
              }}
            >
              {copySuccess.jwk ? "COPIED!" : "COPY"}
            </button>
          )}
        </div>
      </div>
      {!isSymmetric && (
        <>
          <div style={{ marginBottom: 20 }}>
            <label style={styles.label}>PKIX Public Key (PEM)</label>
            <div style={{ position: "relative" }}>
              <pre style={{ ...styles.output, minHeight: "80px" }}>
                {generatedPublicKey || <span style={{ color: "#6c757d", fontStyle: "italic" }}>No public key generated yet</span>}
              </pre>
              {generatedPublicKey && (
                <button
                  onClick={onCopyPublicKey}
                  style={{
                    position: "absolute",
                    top: "10px",
                    right: "10px",
                    background: copySuccess.publicKey ? "#28a745" : "#6c757d",
                    color: "#fff",
                    border: "none",
                    borderRadius: "4px",
                    padding: "4px 8px",
                    fontSize: "12px",
                    fontWeight: 500,
                    cursor: "pointer",
                    fontFamily: "Inter, sans-serif",
                    transition: "background-color 0.2s",
                    zIndex: 10
                  }}
                >
                  {copySuccess.publicKey ? "COPIED!" : "COPY"}
                </button>
              )}
            </div>
          </div>
          <div style={{ marginBottom: 20 }}>
            <label style={styles.label}>PKCS #8 Private Key (PEM)</label>
            <div style={{ position: "relative" }}>
              <pre style={styles.output}>
                {generatedPrivateKey || <span style={{ color: "#6c757d", fontStyle: "italic" }}>No private key generated yet</span>}
              </pre>
              {generatedPrivateKey && (
                <button
                  onClick={onCopyPrivateKey}
                  style={{
                    position: "absolute",
                    top: "10px",
                    right: "10px",
                    background: copySuccess.privateKey ? "#28a745" : "#6c757d",
                    color: "#fff",
                    border: "none",
                    borderRadius: "4px",
                    padding: "4px 8px",
                    fontSize: "12px",
                    fontWeight: 500,
                    cursor: "pointer",
                    fontFamily: "Inter, sans-serif",
                    transition: "background-color 0.2s",
                    zIndex: 10
                  }}
                >
                  {copySuccess.privateKey ? "COPIED!" : "COPY"}
                </button>
              )}
            </div>
          </div>
        </>
      )}
      {isSymmetric && (
        <div style={{ marginBottom: 20 }}>
          <label style={styles.label}>{keyType === 'HMAC' ? 'HMAC Key (Base64)' : 'Symmetric Key (Base64)'}</label>
          <div style={{ position: "relative" }}>
            <pre style={styles.output}>
              {(() => {
                if (!generatedPublicKey) {
                  return <span style={{ color: "#6c757d", fontStyle: "italic" }}>No key generated yet</span>;
                }
                // Remove label if present
                const prefix = 'Symmetric Key (Base64):\n';
                return generatedPublicKey.startsWith(prefix)
                  ? generatedPublicKey.slice(prefix.length)
                  : generatedPublicKey;
              })()}
            </pre>
            {generatedPublicKey && (
              <button
                onClick={onCopyPublicKey}
                style={{
                  position: "absolute",
                  top: "10px",
                  right: "10px",
                  background: copySuccess.publicKey ? "#28a745" : "#6c757d",
                  color: "#fff",
                  border: "none",
                  borderRadius: "4px",
                  padding: "4px 8px",
                  fontSize: "12px",
                  fontWeight: 500,
                  cursor: "pointer",
                  fontFamily: "Inter, sans-serif",
                  transition: "background-color 0.2s",
                  zIndex: 10
                }}
              >
                {copySuccess.publicKey ? "COPIED!" : "COPY"}
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

// Main component
const GenerateNewKey: React.FC = () => {
  const [keyUse, setKeyUse] = useState<string>("sig");
  const [keyType, setKeyType] = useState<string>(KEY_TYPES.RSA);
  const [keyAlgorithm, setKeyAlgorithm] = useState<string>("RS256");
  const [keySize, setKeySize] = useState<number>(2048);
  const [curve, setCurve] = useState<string>("P-256");
  const [keyId, setKeyId] = useState<string>("");
  const [generatedJWK, setGeneratedJWK] = useState<string>("");
  const [generatedPublicKey, setGeneratedPublicKey] = useState<string>("");
  const [generatedPrivateKey, setGeneratedPrivateKey] = useState<string>("");
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string>("");
  const [highlightedJWK, setHighlightedJWK] = useState<string>("");
  const [copySuccess, setCopySuccess] = useState<{ jwk: boolean; publicKey: boolean; privateKey: boolean }>({
    jwk: false,
    publicKey: false,
    privateKey: false
  });
  const jwkPreRef = useRef<HTMLPreElement>(null);
  const [generatedPublicJWK, setGeneratedPublicJWK] = useState<string>("");
  const [highlightedPublicJWK, setHighlightedPublicJWK] = useState<string>("");
  const [copySuccessPublicJWK, setCopySuccessPublicJWK] = useState<boolean>(false);

  // Update key type when key use changes
  useEffect(() => {
    if (keyUse === "sig") {
      if (keyType === KEY_TYPES.X25519 || keyType === KEY_TYPES.AES || keyType === KEY_TYPES.OCT) {
        setKeyType(KEY_TYPES.RSA);
      }
    } else if (keyUse === "enc") {
      if (keyType === KEY_TYPES.ECDSA || keyType === KEY_TYPES.ED25519 || keyType === KEY_TYPES.HMAC) {
        setKeyType(KEY_TYPES.RSA);
      }
    }
  }, [keyUse, keyType]);

  // Update key size when key type changes
  useEffect(() => {
    if (keyType === KEY_TYPES.AES) {
      setKeySize(256); // Default to 256 bits for AES (recommended)
    } else if (keyType === KEY_TYPES.OCT) {
      setKeySize(256); // Default to 256 bits for OCT (recommended)
    } else if (keyType === KEY_TYPES.RSA) {
      setKeySize(2048); // Default to 2048 bits for RSA
    } else if (keyType === KEY_TYPES.HMAC) {
      // Set recommended key size based on HMAC algorithm
      if (keyAlgorithm === "HS256") {
        setKeySize(256); // 256 bits for SHA-256
      } else if (keyAlgorithm === "HS384") {
        setKeySize(384); // 384 bits for SHA-384
      } else if (keyAlgorithm === "HS512") {
        setKeySize(512); // 512 bits for SHA-512
      } else {
        setKeySize(256); // Default for "none" or unknown
      }
    }
  }, [keyType, keyAlgorithm]);



  // Update curve when key type changes to ECDSA
  useEffect(() => {
    if (keyType === KEY_TYPES.ECDSA) {
      setCurve("P-256"); // Default to P-256 for ECDSA
    }
  }, [keyType]);

  // Update algorithm when key type or curve changes
  useEffect(() => {
    if (keyType === KEY_TYPES.ECDSA) {
      const selectedCurve = ECDSA_CURVES.find(c => c.value === curve);
      if (selectedCurve) {
        setKeyAlgorithm(selectedCurve.algorithm);
      }
    } else if (keyType === KEY_TYPES.ED25519) {
      setKeyAlgorithm("EdDSA");
    } else if (keyType === KEY_TYPES.X25519) {
      setKeyAlgorithm("ECDH-ES");
    } else if (keyType === KEY_TYPES.RSA && keyUse === "enc") {
      setKeyAlgorithm("RSA-OAEP"); // Default to RSA-OAEP, not RSA1_5
    } else if (keyType === KEY_TYPES.RSA && keyUse === "sig") {
      setKeyAlgorithm("RS256");
    } else if (keyType === KEY_TYPES.AES) {
      setKeyAlgorithm("A256KW");
    } else if (keyType === KEY_TYPES.OCT) {
      setKeyAlgorithm("dir");
    }
  }, [keyType, curve, keyUse]);

  // Validate and fix algorithm when it becomes invalid for current key type
  useEffect(() => {
    const getAvailableAlgorithms = () => {
      if (keyUse === "sig") {
        switch (keyType) {
          case KEY_TYPES.RSA: return RSA_SIGNATURE_ALGORITHMS;
          case KEY_TYPES.ECDSA: return ECDSA_ALGORITHMS;
          case KEY_TYPES.ED25519: return ED25519_ALGORITHMS;
          case KEY_TYPES.HMAC: return [...HMAC_ALGORITHMS, ...NONE_ALGORITHMS];
          default: return RSA_SIGNATURE_ALGORITHMS;
        }
      } else {
        switch (keyType) {
          case KEY_TYPES.RSA: return RSA_ENCRYPTION_ALGORITHMS;
          case KEY_TYPES.X25519: return ECDH_ALGORITHMS;
          case KEY_TYPES.AES: return AES_KEY_WRAP_ALGORITHMS;
          case KEY_TYPES.OCT: return [...PBES2_ALGORITHMS, ...DIRECT_ALGORITHMS];
          default: return RSA_ENCRYPTION_ALGORITHMS;
        }
      }
    };

    const availableAlgorithms = getAvailableAlgorithms();
    const isValidAlgorithm = availableAlgorithms.some(alg => alg.value === keyAlgorithm);
    
    if (!isValidAlgorithm && availableAlgorithms.length > 0 && availableAlgorithms[0]) {
      setKeyAlgorithm(availableAlgorithms[0].value);
    }
  }, [keyType, keyUse, keyAlgorithm]);

  // Clear generated results when key parameters change
  useEffect(() => {
    setGeneratedJWK("");
    setGeneratedPublicKey("");
    setGeneratedPrivateKey("");
    setError("");
  }, [keyType, keyUse, keyAlgorithm, keySize, curve]);

  // Handle syntax highlighting for JWK
  useEffect(() => {
    if (generatedJWK) {
      const jsonGrammar = Prism.languages['json'];
      if (jsonGrammar) {
        setHighlightedJWK(Prism.highlight(generatedJWK, jsonGrammar, "json"));
      } else {
        setHighlightedJWK(generatedJWK);
      }
    } else {
      setHighlightedJWK("");
    }
  }, [generatedJWK]);

  // Highlight public JWK
  useEffect(() => {
    if (generatedPublicJWK) {
      const jsonGrammar = Prism.languages['json'];
      if (jsonGrammar) {
        setHighlightedPublicJWK(Prism.highlight(generatedPublicJWK, jsonGrammar, "json"));
      } else {
        setHighlightedPublicJWK(generatedPublicJWK);
      }
    } else {
      setHighlightedPublicJWK("");
    }
  }, [generatedPublicJWK]);


  const handleGenerate = async () => {
    setIsLoading(true);
    setError("");
    setGeneratedJWK("");
    setGeneratedPublicJWK("");
    setGeneratedPublicKey("");
    setGeneratedPrivateKey("");

    try {
      let keyPair: CryptoKeyPair | CryptoKey;
      let isSymmetric = false;
      let isAsymmetric = false;

      switch (keyType) {
        case KEY_TYPES.RSA:
        case KEY_TYPES.ECDSA:
        case KEY_TYPES.ED25519:
        case KEY_TYPES.X25519:
          isAsymmetric = true;
          break;
      }

      switch (keyType) {
        case KEY_TYPES.RSA:
          keyPair = await generateRSAKey(keyUse, keyAlgorithm, keySize, []);
          break;
        case KEY_TYPES.ECDSA:
          keyPair = await generateECDSAKey(curve, []);
          break;
        case KEY_TYPES.ED25519:
          keyPair = await generateEd25519Key([]);
          break;
        case KEY_TYPES.X25519:
          keyPair = await generateX25519Key([]);
          break;
        case KEY_TYPES.HMAC:
          if (keyAlgorithm === "none") {
            // For none algorithm, create a dummy key (not actually used for signing)
            const dummyKey = crypto.getRandomValues(new Uint8Array(32));
            keyPair = await crypto.subtle.importKey(
              "raw",
              dummyKey,
              { name: "HMAC", hash: "SHA-256" },
              false,
              ["sign", "verify"]
            );
            isSymmetric = true;
          } else {
            keyPair = await generateHMACKey(keyAlgorithm, keySize, []);
            isSymmetric = true;
          }
          break;
        case KEY_TYPES.AES:
          keyPair = await generateAESKey(keySize, []);
          isSymmetric = true;
          break;
        case KEY_TYPES.OCT:
          keyPair = await generateOctKey(keySize, []);
          isSymmetric = true;
          break;
        default:
          throw new Error("Unsupported key type");
      }

      // Generate key ID if not provided
      let finalKeyId = keyId;
      if (!keyId.trim()) {
        if (isSymmetric) {
          // For symmetric keys, generate a fingerprint from the key itself
          const keyData = await crypto.subtle.exportKey("raw", keyPair as CryptoKey);
          const hash = await crypto.subtle.digest("SHA-256", keyData);
          const hashArray = new Uint8Array(hash);
          // Convert to base64 format like SSH-keygen SHA256 fingerprint
          finalKeyId = btoa(String.fromCharCode(...hashArray));
        } else {
          finalKeyId = await generateFingerprint((keyPair as CryptoKeyPair).publicKey);
        }
      }

      // Convert to JWK
      if (isAsymmetric) {
        // Public JWK
        const publicJWK = await cryptoKeyToJWK(
          (keyPair as CryptoKeyPair).publicKey,
          finalKeyId,
          keyAlgorithm,
          keyUse
        );
        setGeneratedPublicJWK(publicJWK);
      } else {
        setGeneratedPublicJWK("");
      }
      // Private JWK (or symmetric)
      const jwk = await cryptoKeyToJWK(
        isSymmetric ? keyPair as CryptoKey : (keyPair as CryptoKeyPair).privateKey, 
        finalKeyId, 
        keyAlgorithm, 
        keyUse
      );
      setGeneratedJWK(jwk);

      // Convert to PEM formats (only for asymmetric keys)
      if (!isSymmetric) {
        const publicKeyPEM = await cryptoKeyToPEM((keyPair as CryptoKeyPair).publicKey, false);
        const privateKeyPEM = await cryptoKeyToPEM((keyPair as CryptoKeyPair).privateKey, true);
        setGeneratedPublicKey(publicKeyPEM);
        setGeneratedPrivateKey(privateKeyPEM);
      } else {
        const keyData = await crypto.subtle.exportKey("raw", keyPair as CryptoKey);
        const keyBase64 = arrayBufferToBase64(keyData);
        setGeneratedPublicKey(`Symmetric Key (Base64):\n${keyBase64}`);
        setGeneratedPrivateKey("");
      }
    } catch (err) {
      console.error("Key generation error:", err);
      setError(err instanceof Error ? err.message : "An unknown error occurred");
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopyJWK = async (): Promise<void> => {
    if (generatedJWK) {
      try {
        await navigator.clipboard.writeText(generatedJWK);
        setCopySuccess(prev => ({ ...prev, jwk: true }));
        setTimeout(() => setCopySuccess(prev => ({ ...prev, jwk: false })), 2000);
      } catch (err) {
        console.error("Failed to copy JWK to clipboard:", err);
      }
    }
  };

  const handleCopyPublicKey = async (): Promise<void> => {
    if (generatedPublicKey) {
      try {
        // For symmetric keys, strip the label and only copy the actual key data
        const isSymmetric = keyType === KEY_TYPES.AES || keyType === KEY_TYPES.OCT || keyType === KEY_TYPES.HMAC;
        let textToCopy = generatedPublicKey;
        
        if (isSymmetric) {
          // Remove label if present
          const prefix = 'Symmetric Key (Base64):\n';
          if (generatedPublicKey.startsWith(prefix)) {
            textToCopy = generatedPublicKey.slice(prefix.length);
          }
        }
        
        await navigator.clipboard.writeText(textToCopy);
        setCopySuccess(prev => ({ ...prev, publicKey: true }));
        setTimeout(() => setCopySuccess(prev => ({ ...prev, publicKey: false })), 2000);
      } catch (err) {
        console.error("Failed to copy public key to clipboard:", err);
      }
    }
  };

  const handleCopyPrivateKey = async (): Promise<void> => {
    if (generatedPrivateKey) {
      try {
        await navigator.clipboard.writeText(generatedPrivateKey);
        setCopySuccess(prev => ({ ...prev, privateKey: true }));
        setTimeout(() => setCopySuccess(prev => ({ ...prev, privateKey: false })), 2000);
      } catch (err) {
        console.error("Failed to copy private key to clipboard:", err);
      }
    }
  };

  const handleCopyPublicJWK = async (): Promise<void> => {
    if (generatedPublicJWK) {
      try {
        await navigator.clipboard.writeText(generatedPublicJWK);
        setCopySuccessPublicJWK(true);
        setTimeout(() => setCopySuccessPublicJWK(false), 2000);
      } catch (err) {
        console.error("Failed to copy public JWK to clipboard:", err);
      }
    }
  };

  return (
    <div style={{ fontFamily: "Inter, sans-serif", color: "#495057", padding: "16px", width: "100%", height: "100%", boxSizing: "border-box", overflow: "hidden" }}>
      <KeyUseSelector value={keyUse} onChange={setKeyUse} />
      
      <KeyTypeSelector value={keyType} onChange={setKeyType} keyUse={keyUse} />
      
      <KeyAlgorithmSelector 
        value={keyAlgorithm} 
        onChange={setKeyAlgorithm} 
        keyType={keyType} 
        keyUse={keyUse} 
      />

      {(keyType === KEY_TYPES.RSA || keyType === KEY_TYPES.AES || keyType === KEY_TYPES.OCT || keyType === KEY_TYPES.HMAC) && keyAlgorithm !== "none" && (
        <KeySizeSelector value={keySize} onChange={setKeySize} keyType={keyType} />
      )}

      {keyType === KEY_TYPES.ECDSA && (
        <CurveSelector value={curve} onChange={setCurve} />
      )}

      {keyType === KEY_TYPES.ED25519 && <Ed25519Info />}
      {keyType === KEY_TYPES.X25519 && <X25519Info />}
      {keyAlgorithm === "RSA1_5" && <RSA1_5Warning />}
      {keyAlgorithm === "none" && <NoneAlgorithmInfo />}

      <KeyIdSelector value={keyId} onChange={setKeyId} />

      <button
        onClick={handleGenerate}
        disabled={isLoading}
        style={{ 
          ...styles.button,
          ...(isLoading ? styles.buttonDisabled : {})
        }}
      >
        {isLoading ? "Generating..." : "Generate Key"}
      </button>

      {error && (
        <div style={styles.error}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {(generatedJWK || generatedPublicKey || generatedPrivateKey) && (
        <ResultsSection
          generatedJWK={generatedJWK}
          generatedPublicKey={generatedPublicKey}
          generatedPrivateKey={generatedPrivateKey}
          highlightedJWK={highlightedJWK}
          jwkPreRef={jwkPreRef}
          onCopyJWK={handleCopyJWK}
          onCopyPublicKey={handleCopyPublicKey}
          onCopyPrivateKey={handleCopyPrivateKey}
          copySuccess={copySuccess}
          generatedPublicJWK={generatedPublicJWK}
          highlightedPublicJWK={highlightedPublicJWK}
          onCopyPublicJWK={handleCopyPublicJWK}
          copySuccessPublicJWK={copySuccessPublicJWK}
          showPublicJWK={!!generatedPublicJWK}
          keyType={keyType}
        />
      )}
    </div>
  );
};

export default GenerateNewKey; 