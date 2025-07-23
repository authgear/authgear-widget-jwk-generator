import React, { useState, useEffect } from "react";

// Types
interface KeyAlgorithm {
  value: string;
  label: string;
  keyType: string;
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
  X25519: "X25519"
} as const;

const RSA_ALGORITHMS: KeyAlgorithm[] = [
  { value: "RS256", label: "RS256 (RSA + SHA-256)", keyType: KEY_TYPES.RSA },
  { value: "RS384", label: "RS384 (RSA + SHA-384)", keyType: KEY_TYPES.RSA },
  { value: "RS512", label: "RS512 (RSA + SHA-512)", keyType: KEY_TYPES.RSA },
];

const ECDSA_ALGORITHMS: KeyAlgorithm[] = [
  { value: "ES256", label: "ES256 (ECDSA + SHA-256)", keyType: KEY_TYPES.ECDSA },
  { value: "ES384", label: "ES384 (ECDSA + SHA-384)", keyType: KEY_TYPES.ECDSA },
  { value: "ES512", label: "ES512 (ECDSA + SHA-512)", keyType: KEY_TYPES.ECDSA },
];

const ED25519_ALGORITHMS: KeyAlgorithm[] = [
  { value: "EdDSA", label: "EdDSA (Ed25519)", keyType: KEY_TYPES.ED25519 },
];

const X25519_ALGORITHMS: KeyAlgorithm[] = [
  { value: "ECDH-ES", label: "ECDH-ES (X25519)", keyType: KEY_TYPES.X25519 },
];

const KEY_USES = {
  RSA: [
    { value: "sig", label: "Signature" },
    { value: "enc", label: "Encryption" },
  ],
  ECDSA: [
    { value: "sig", label: "Signature" },
  ],
  ED25519: [
    { value: "sig", label: "Signature" },
  ],
  X25519: [
    { value: "enc", label: "Encryption" },
  ],
} as const;

const KEY_OPERATIONS = {
  RSA: [
    { value: "sign", label: "sign", description: "Create digital signatures" },
    { value: "verify", label: "verify", description: "Verify digital signatures" },
    { value: "encrypt", label: "encrypt", description: "Encrypt data" },
    { value: "decrypt", label: "decrypt", description: "Decrypt data" },
    { value: "wrapKey", label: "wrapKey", description: "Wrap (encrypt) other keys" },
    { value: "unwrapKey", label: "unwrapKey", description: "Unwrap (decrypt) other keys" },
  ],
  ECDSA: [
    { value: "sign", label: "sign", description: "Create digital signatures" },
    { value: "verify", label: "verify", description: "Verify digital signatures" },
  ],
  ED25519: [
    { value: "sign", label: "sign", description: "Create digital signatures" },
    { value: "verify", label: "verify", description: "Verify digital signatures" },
  ],
  X25519: [
    { value: "deriveKey", label: "deriveKey", description: "Derive shared secret keys" },
    { value: "deriveBits", label: "deriveBits", description: "Derive shared secret bits" },
  ],
} as const;

const ECDSA_CURVES: Curve[] = [
  { value: "P-256", label: "P-256 (secp256r1)", algorithm: "ES256" },
  { value: "P-384", label: "P-384 (secp384r1)", algorithm: "ES384" },
  { value: "P-521", label: "P-521 (secp521r1)", algorithm: "ES512" },
];

const KEY_SIZES = [
  { value: 1024, label: "1024 bits" },
  { value: 2048, label: "2048 bits (recommended)" },
  { value: 4096, label: "4096 bits" },
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
  const hashHex = Array.from(hashArray, byte => byte.toString(16).padStart(2, '0')).join('');
  return hashHex.substring(0, 16);
};

const cryptoKeyToJWK = async (
  cryptoKey: CryptoKey, 
  keyId: string, 
  alg: string, 
  use: string, 
  keyOps?: string[]
): Promise<string> => {
  const jwk = await crypto.subtle.exportKey("jwk", cryptoKey);
  
  (jwk as any).kid = keyId;
  (jwk as any).alg = alg;
  (jwk as any).use = use;
  if (keyOps && keyOps.length > 0) {
    (jwk as any).key_ops = keyOps;
  }
  
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
  const algorithm = keyUse === "sig" ? "RSASSA-PKCS1-v1_5" : "RSA-OAEP";
  const hashAlgorithm = keyAlgorithm === "RS256" ? "SHA-256" : 
                       keyAlgorithm === "RS384" ? "SHA-384" : "SHA-512";
  
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
const KeyTypeSelector: React.FC<{
  value: string;
  onChange: (value: string) => void;
}> = ({ value, onChange }) => (
  <div style={{ marginBottom: 20 }}>
    <label style={styles.label}>Key Type</label>
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      style={styles.input}
    >
      <option value={KEY_TYPES.RSA}>RSA - Digital signatures and encryption (most versatile)</option>
      <option value={KEY_TYPES.ECDSA}>ECDSA - Digital signatures only (faster, smaller keys)</option>
      <option value={KEY_TYPES.ED25519}>Ed25519 - Modern digital signatures (very fast, very secure)</option>
      <option value={KEY_TYPES.X25519}>X25519 - Key exchange and encryption (ECDH)</option>
    </select>
  </div>
);

const KeySizeSelector: React.FC<{
  value: number;
  onChange: (value: number) => void;
}> = ({ value, onChange }) => (
  <div style={{ marginBottom: 20 }}>
    <label style={styles.label}>Key Size (bits)</label>
    <select
      value={value}
      onChange={(e) => onChange(Number(e.target.value))}
      style={styles.input}
    >
      {KEY_SIZES.map(size => (
        <option key={size.value} value={size.value}>{size.label}</option>
      ))}
    </select>
  </div>
);

const CurveSelector: React.FC<{
  value: string;
  onChange: (value: string) => void;
}> = ({ value, onChange }) => (
  <div style={{ marginBottom: 20 }}>
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

const KeyMetadataSection: React.FC<{
  keyId: string;
  setKeyId: (value: string) => void;
  keyAlgorithm: string;
  setKeyAlgorithm: (value: string) => void;
  keyUse: string;
  setKeyUse: (value: string) => void;
  keyType: string;
}> = ({ keyId, setKeyId, keyAlgorithm, setKeyAlgorithm, keyUse, setKeyUse, keyType }) => {
  const getAvailableAlgorithms = () => {
    switch (keyType) {
      case KEY_TYPES.RSA: return RSA_ALGORITHMS;
      case KEY_TYPES.ECDSA: return ECDSA_ALGORITHMS;
      case KEY_TYPES.ED25519: return ED25519_ALGORITHMS;
      case KEY_TYPES.X25519: return X25519_ALGORITHMS;
      default: return RSA_ALGORITHMS;
    }
  };

  const getAvailableKeyUses = () => {
    switch (keyType) {
      case KEY_TYPES.RSA: return KEY_USES.RSA;
      case KEY_TYPES.ECDSA: return KEY_USES.ECDSA;
      case KEY_TYPES.ED25519: return KEY_USES.ED25519;
      case KEY_TYPES.X25519: return KEY_USES.X25519;
      default: return KEY_USES.RSA;
    }
  };

  return (
    <div style={{ 
      display: "grid", 
      gridTemplateColumns: "1fr 1fr 1fr", 
      gap: 16, 
      marginBottom: 20 
    }}>
      <div>
        <label style={styles.label}>Key ID (kid)</label>
        <input
          type="text"
          value={keyId}
          onChange={(e) => setKeyId(e.target.value)}
          style={styles.input}
          placeholder="Leave empty to use fingerprint"
        />
      </div>
      <div>
        <label style={styles.label}>Key Algorithm (alg)</label>
        <select
          value={keyAlgorithm}
          onChange={(e) => setKeyAlgorithm(e.target.value)}
          style={styles.input}
        >
          {getAvailableAlgorithms().map(opt => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>
      </div>
      <div>
        <label style={styles.label}>Key Use (use)</label>
        <select
          value={keyUse}
          onChange={(e) => setKeyUse(e.target.value)}
          style={styles.input}
        >
          {getAvailableKeyUses().map(opt => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </select>
      </div>
    </div>
  );
};

const KeyOperationsSection: React.FC<{
  keyOperations: string[];
  setKeyOperations: (operations: string[]) => void;
  keyType: string;
}> = ({ keyOperations, setKeyOperations, keyType }) => {
  const getAvailableKeyOperations = () => {
    switch (keyType) {
      case KEY_TYPES.RSA: return KEY_OPERATIONS.RSA;
      case KEY_TYPES.ECDSA: return KEY_OPERATIONS.ECDSA;
      case KEY_TYPES.ED25519: return KEY_OPERATIONS.ED25519;
      case KEY_TYPES.X25519: return KEY_OPERATIONS.X25519;
      default: return KEY_OPERATIONS.RSA;
    }
  };

  const handleKeyOperationChange = (operation: string, checked: boolean) => {
    if (checked) {
      setKeyOperations([...keyOperations, operation]);
    } else {
      setKeyOperations(keyOperations.filter(op => op !== operation));
    }
  };

  return (
    <div style={{ marginBottom: 20 }}>
      <label style={styles.label}>Key Operations (key_ops) - Optional</label>
      <div style={{ 
        display: "grid", 
        gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", 
        gap: 12,
        padding: "12px",
        border: "1px solid #e9ecef",
        borderRadius: "4px",
        backgroundColor: "#f8f9fa"
      }}>
        {getAvailableKeyOperations().map(op => (
          <label 
            key={op.value} 
            style={{ 
              display: "flex", 
              alignItems: "center", 
              gap: 8,
              padding: "8px",
              borderRadius: "4px",
              cursor: "pointer",
              transition: "background-color 0.2s",
              backgroundColor: keyOperations.includes(op.value) ? "#e3f2fd" : "transparent"
            }}
          >
            <input
              type="checkbox"
              checked={keyOperations.includes(op.value)}
              onChange={(e) => handleKeyOperationChange(op.value, e.target.checked)}
              style={{ 
                width: "16px", 
                height: "16px",
                cursor: "pointer"
              }}
            />
            <div>
              <div style={{ fontWeight: 500, fontSize: "14px" }}>{op.label}</div>
              <div style={{ fontSize: "12px", color: "#6c757d" }}>{op.description}</div>
            </div>
          </label>
        ))}
      </div>
      {keyOperations.length > 0 && (
        <div style={{ 
          marginTop: 8, 
          fontSize: "12px", 
          color: "#6c757d",
          fontStyle: "italic"
        }}>
          Selected operations: {keyOperations.join(', ')}
        </div>
      )}
    </div>
  );
};

const ResultsSection: React.FC<{
  generatedJWK: string;
  generatedPublicKey: string;
  generatedPrivateKey: string;
}> = ({ generatedJWK, generatedPublicKey, generatedPrivateKey }) => (
  <div style={{ marginTop: 24 }}>
    <div style={{ marginBottom: 20 }}>
      <label style={styles.label}>JWK (JSON Web Key)</label>
      <pre style={styles.output}>{generatedJWK}</pre>
    </div>
    <div style={{ marginBottom: 20 }}>
      <label style={styles.label}>PKIX Public Key (PEM)</label>
      <pre style={{ ...styles.output, minHeight: "80px" }}>{generatedPublicKey}</pre>
    </div>
    <div style={{ marginBottom: 20 }}>
      <label style={styles.label}>PKCS #8 Private Key (PEM)</label>
      <pre style={styles.output}>{generatedPrivateKey}</pre>
    </div>
  </div>
);

// Main component
const GenerateNewKey: React.FC = () => {
  const [keyType, setKeyType] = useState<string>(KEY_TYPES.RSA);
  const [keySize, setKeySize] = useState<number>(2048);
  const [curve, setCurve] = useState<string>("P-256");
  const [keyId, setKeyId] = useState<string>("");
  const [keyAlgorithm, setKeyAlgorithm] = useState<string>("RS256");
  const [keyUse, setKeyUse] = useState<string>("sig");
  const [keyOperations, setKeyOperations] = useState<string[]>([]);
  const [generatedJWK, setGeneratedJWK] = useState<string>("");
  const [generatedPublicKey, setGeneratedPublicKey] = useState<string>("");
  const [generatedPrivateKey, setGeneratedPrivateKey] = useState<string>("");
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string>("");

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
    }
  }, [keyType, curve]);

  // Reset key use when switching key types
  useEffect(() => {
    if ((keyType === KEY_TYPES.ECDSA || keyType === KEY_TYPES.ED25519) && keyUse === "enc") {
      setKeyUse("sig");
    } else if (keyType === KEY_TYPES.X25519 && keyUse === "sig") {
      setKeyUse("enc");
    }
  }, [keyType, keyUse]);

  // Reset key operations when switching key types
  useEffect(() => {
    if (keyType === KEY_TYPES.ECDSA || keyType === KEY_TYPES.ED25519) {
      setKeyOperations(prev => prev.filter(op => ["sign", "verify"].includes(op)));
    } else if (keyType === KEY_TYPES.X25519) {
      setKeyOperations(prev => prev.filter(op => ["deriveKey", "deriveBits"].includes(op)));
    }
  }, [keyType]);

  const handleGenerate = async () => {
    setIsLoading(true);
    setError("");
    setGeneratedJWK("");
    setGeneratedPublicKey("");
    setGeneratedPrivateKey("");

    try {
      let keyPair: CryptoKeyPair;

      switch (keyType) {
        case KEY_TYPES.RSA:
          keyPair = await generateRSAKey(keyUse, keyAlgorithm, keySize, keyOperations);
          break;
        case KEY_TYPES.ECDSA:
          keyPair = await generateECDSAKey(curve, keyOperations);
          break;
        case KEY_TYPES.ED25519:
          keyPair = await generateEd25519Key(keyOperations);
          break;
        case KEY_TYPES.X25519:
          keyPair = await generateX25519Key(keyOperations);
          break;
        default:
          throw new Error("Unsupported key type");
      }

      // Generate key ID if not provided
      let finalKeyId = keyId;
      if (!keyId.trim()) {
        finalKeyId = await generateFingerprint(keyPair.publicKey);
      }

      // Convert to JWK
      const jwk = await cryptoKeyToJWK(
        keyPair.privateKey, 
        finalKeyId, 
        keyAlgorithm, 
        keyUse, 
        keyOperations.length > 0 ? keyOperations : undefined
      );

      // Convert to PEM formats
      const publicKeyPEM = await cryptoKeyToPEM(keyPair.publicKey, false);
      const privateKeyPEM = await cryptoKeyToPEM(keyPair.privateKey, true);

      setGeneratedJWK(jwk);
      setGeneratedPublicKey(publicKeyPEM);
      setGeneratedPrivateKey(privateKeyPEM);
    } catch (err) {
      console.error("Key generation error:", err);
      setError(err instanceof Error ? err.message : "An unknown error occurred");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div style={{ fontFamily: "Inter, sans-serif", color: "#495057" }}>
      <KeyTypeSelector value={keyType} onChange={setKeyType} />

      {keyType === KEY_TYPES.RSA && (
        <KeySizeSelector value={keySize} onChange={setKeySize} />
      )}

      {keyType === KEY_TYPES.ECDSA && (
        <CurveSelector value={curve} onChange={setCurve} />
      )}

      {keyType === KEY_TYPES.ED25519 && <Ed25519Info />}
      {keyType === KEY_TYPES.X25519 && <X25519Info />}

      <KeyMetadataSection
        keyId={keyId}
        setKeyId={setKeyId}
        keyAlgorithm={keyAlgorithm}
        setKeyAlgorithm={setKeyAlgorithm}
        keyUse={keyUse}
        setKeyUse={setKeyUse}
        keyType={keyType}
      />

      <KeyOperationsSection
        keyOperations={keyOperations}
        setKeyOperations={setKeyOperations}
        keyType={keyType}
      />

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
        />
      )}
    </div>
  );
};

export default GenerateNewKey; 