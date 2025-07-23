import React, { useState } from "react";

interface KeyAlgorithm {
  value: string;
  label: string;
  keyType: string;
}

interface KeyUse {
  value: string;
  label: string;
}

interface KeyOperation {
  value: string;
  label: string;
  description: string;
}

interface Curve {
  value: string;
  label: string;
  algorithm: string;
}

const RSA_ALGORITHMS: KeyAlgorithm[] = [
  { value: "RS256", label: "RS256 (RSA + SHA-256)", keyType: "RSA" },
  { value: "RS384", label: "RS384 (RSA + SHA-384)", keyType: "RSA" },
  { value: "RS512", label: "RS512 (RSA + SHA-512)", keyType: "RSA" },
];

const ECDSA_ALGORITHMS: KeyAlgorithm[] = [
  { value: "ES256", label: "ES256 (ECDSA + SHA-256)", keyType: "ECDSA" },
  { value: "ES384", label: "ES384 (ECDSA + SHA-384)", keyType: "ECDSA" },
  { value: "ES512", label: "ES512 (ECDSA + SHA-512)", keyType: "ECDSA" },
];

const RSA_KEY_USES: KeyUse[] = [
  { value: "sig", label: "Signature" },
  { value: "enc", label: "Encryption" },
];

const ECDSA_KEY_USES: KeyUse[] = [
  { value: "sig", label: "Signature" },
];

const RSA_KEY_OPERATIONS: KeyOperation[] = [
  { value: "sign", label: "sign", description: "Create digital signatures" },
  { value: "verify", label: "verify", description: "Verify digital signatures" },
  { value: "encrypt", label: "encrypt", description: "Encrypt data" },
  { value: "decrypt", label: "decrypt", description: "Decrypt data" },
  { value: "wrapKey", label: "wrapKey", description: "Wrap (encrypt) other keys" },
  { value: "unwrapKey", label: "unwrapKey", description: "Unwrap (decrypt) other keys" },
];

const ECDSA_KEY_OPERATIONS: KeyOperation[] = [
  { value: "sign", label: "sign", description: "Create digital signatures" },
  { value: "verify", label: "verify", description: "Verify digital signatures" },
];

const ECDSA_CURVES: Curve[] = [
  { value: "P-256", label: "P-256 (secp256r1)", algorithm: "ES256" },
  { value: "P-384", label: "P-384 (secp384r1)", algorithm: "ES384" },
  { value: "P-521", label: "P-521 (secp521r1)", algorithm: "ES512" },
];

// Utility function to convert ArrayBuffer to base64
const arrayBufferToBase64 = (buffer: ArrayBuffer): string => {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i] || 0);
  }
  return btoa(binary);
};

// Utility function to convert base64 to ArrayBuffer
const base64ToArrayBuffer = (base64: string): ArrayBuffer => {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
};

// Convert CryptoKey to JWK
const cryptoKeyToJWK = async (cryptoKey: CryptoKey, keyId: string, alg: string, use: string, keyOps?: string[]): Promise<string> => {
  const jwk = await crypto.subtle.exportKey("jwk", cryptoKey);
  
  // Add metadata
  (jwk as any).kid = keyId;
  (jwk as any).alg = alg;
  (jwk as any).use = use;
  if (keyOps && keyOps.length > 0) {
    (jwk as any).key_ops = keyOps;
  }
  
  return JSON.stringify(jwk, null, 2);
};

// Convert CryptoKey to PEM format
const cryptoKeyToPEM = async (cryptoKey: CryptoKey, isPrivate: boolean): Promise<string> => {
  const format = isPrivate ? "pkcs8" : "spki";
  const exported = await crypto.subtle.exportKey(format, cryptoKey);
  const base64 = arrayBufferToBase64(exported);
  
  const header = isPrivate ? "-----BEGIN PRIVATE KEY-----" : "-----BEGIN PUBLIC KEY-----";
  const footer = isPrivate ? "-----END PRIVATE KEY-----" : "-----END PUBLIC KEY-----";
  
  // Split base64 into 64-character lines
  const lines = [];
  for (let i = 0; i < base64.length; i += 64) {
    lines.push(base64.slice(i, i + 64));
  }
  
  return `${header}\n${lines.join('\n')}\n${footer}`;
};

// Generate fingerprint from public key
const generateFingerprint = async (publicKey: CryptoKey): Promise<string> => {
  const exported = await crypto.subtle.exportKey("spki", publicKey);
  const hash = await crypto.subtle.digest("SHA-256", exported);
  const hashArray = new Uint8Array(hash);
  const hashHex = Array.from(hashArray, byte => byte.toString(16).padStart(2, '0')).join('');
  
  // Return first 16 characters as fingerprint
  return hashHex.substring(0, 16);
};

const GenerateNewKey: React.FC = () => {
  const [keyType, setKeyType] = useState<string>("RSA");
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

  // Get available algorithms based on key type
  const getAvailableAlgorithms = () => {
    return keyType === "RSA" ? RSA_ALGORITHMS : ECDSA_ALGORITHMS;
  };

  // Get available key uses based on key type
  const getAvailableKeyUses = () => {
    return keyType === "RSA" ? RSA_KEY_USES : ECDSA_KEY_USES;
  };

  // Get available key operations based on key type
  const getAvailableKeyOperations = () => {
    return keyType === "RSA" ? RSA_KEY_OPERATIONS : ECDSA_KEY_OPERATIONS;
  };

  // Update algorithm when key type or curve changes
  React.useEffect(() => {
    if (keyType === "ECDSA") {
      const selectedCurve = ECDSA_CURVES.find(c => c.value === curve);
      if (selectedCurve) {
        setKeyAlgorithm(selectedCurve.algorithm);
      }
    }
  }, [keyType, curve]);

  // Reset key use when switching key types
  React.useEffect(() => {
    if (keyType === "ECDSA" && keyUse === "enc") {
      setKeyUse("sig");
    }
  }, [keyType, keyUse]);

  // Reset key operations when switching key types
  React.useEffect(() => {
    if (keyType === "ECDSA") {
      // Remove encryption-related operations for ECDSA
      setKeyOperations(prev => prev.filter(op => ["sign", "verify"].includes(op)));
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

      if (keyType === "RSA") {
        // RSA key generation
        const algorithm = keyUse === "sig" ? "RSASSA-PKCS1-v1_5" : "RSA-OAEP";
        const hashAlgorithm = keyAlgorithm === "RS256" ? "SHA-256" : 
                             keyAlgorithm === "RS384" ? "SHA-384" : "SHA-512";
        
        // Determine key usages - if no operations selected, use defaults based on key use
        let keyUsages: KeyUsage[];
        if (keyOperations.length === 0) {
          keyUsages = keyUse === "sig" ? ["sign", "verify"] : ["encrypt", "decrypt"];
        } else {
          keyUsages = keyOperations as KeyUsage[];
        }
        
        keyPair = await crypto.subtle.generateKey(
          {
            name: algorithm,
            modulusLength: keySize,
            publicExponent: new Uint8Array([1, 0, 1]), // 65537
            hash: hashAlgorithm,
          } as RsaHashedKeyGenParams,
          true, // extractable
          keyUsages
        );
      } else {
        // ECDSA key generation
        const hashAlgorithm = keyAlgorithm === "ES256" ? "SHA-256" : 
                             keyAlgorithm === "ES384" ? "SHA-384" : "SHA-512";
        
        // Determine key usages - ECDSA only supports sign/verify
        let keyUsages: KeyUsage[];
        if (keyOperations.length === 0) {
          keyUsages = ["sign", "verify"];
        } else {
          keyUsages = keyOperations as KeyUsage[];
        }
        
        keyPair = await crypto.subtle.generateKey(
          {
            name: "ECDSA",
            namedCurve: curve,
          } as EcKeyGenParams,
          true, // extractable
          keyUsages
        );
      }

      // Generate key ID if not provided
      let finalKeyId = keyId;
      if (!keyId.trim()) {
        finalKeyId = await generateFingerprint(keyPair.publicKey);
      }

      // Convert to JWK - only include key_ops if operations were explicitly selected
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

  const handleKeyOperationChange = (operation: string, checked: boolean) => {
    if (checked) {
      setKeyOperations([...keyOperations, operation]);
    } else {
      setKeyOperations(keyOperations.filter(op => op !== operation));
    }
  };

  const commonInputStyle: React.CSSProperties = {
    width: "100%",
    padding: "8px 12px",
    borderRadius: "4px",
    border: "1px solid #dee2e6",
    fontSize: "14px",
    fontFamily: "Inter, sans-serif",
    outline: "none",
    transition: "border-color 0.2s",
    boxSizing: "border-box",
    color: "#495057",
    backgroundColor: "#fff"
  };

  const commonLabelStyle: React.CSSProperties = {
    fontWeight: 600,
    color: "#495057",
    fontSize: "14px",
    marginBottom: "6px",
    display: "block",
    fontFamily: "Inter, sans-serif"
  };

  return (
    <div style={{ fontFamily: "Inter, sans-serif", color: "#495057" }}>
      {/* Key Type Selection */}
      <div style={{ marginBottom: 20 }}>
        <label style={commonLabelStyle}>Key Type</label>
        <select
          value={keyType}
          onChange={(e) => setKeyType(e.target.value)}
          style={commonInputStyle}
        >
          <option value="RSA">RSA - Digital signatures and encryption (most versatile)</option>
          <option value="ECDSA">ECDSA - Digital signatures only (faster, smaller keys)</option>
          <option value="Ed25519" disabled>Ed25519 - Modern digital signatures (Coming soon)</option>
          <option value="X25519" disabled>X25519 - Key exchange and encryption (Coming soon)</option>
        </select>
      </div>

      {/* Key Size Selection (only for RSA) */}
      {keyType === "RSA" && (
        <div style={{ marginBottom: 20 }}>
          <label style={commonLabelStyle}>Key Size (bits)</label>
          <select
            value={keySize}
            onChange={(e) => setKeySize(Number(e.target.value))}
            style={commonInputStyle}
          >
            <option value={1024}>1024 bits</option>
            <option value={2048}>2048 bits (recommended)</option>
            <option value={4096}>4096 bits</option>
          </select>
        </div>
      )}

      {/* Curve Selection (only for ECDSA) */}
      {keyType === "ECDSA" && (
        <div style={{ marginBottom: 20 }}>
          <label style={commonLabelStyle}>Curve</label>
          <select
            value={curve}
            onChange={(e) => setCurve(e.target.value)}
            style={commonInputStyle}
          >
            {ECDSA_CURVES.map(curveOption => (
              <option key={curveOption.value} value={curveOption.value}>
                {curveOption.label}
              </option>
            ))}
          </select>
        </div>
      )}

      {/* Key Metadata Section */}
      <div style={{ 
        display: "grid", 
        gridTemplateColumns: "1fr 1fr 1fr", 
        gap: 16, 
        marginBottom: 20 
      }}>
        <div>
          <label style={commonLabelStyle}>Key ID (kid)</label>
          <input
            type="text"
            value={keyId}
            onChange={(e) => setKeyId(e.target.value)}
            style={commonInputStyle}
            placeholder="Leave empty to use fingerprint"
          />
        </div>
        <div>
          <label style={commonLabelStyle}>Key Algorithm (alg)</label>
          <select
            value={keyAlgorithm}
            onChange={(e) => setKeyAlgorithm(e.target.value)}
            style={commonInputStyle}
          >
            {getAvailableAlgorithms().map(opt => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>
        <div>
          <label style={commonLabelStyle}>Key Use (use)</label>
          <select
            value={keyUse}
            onChange={(e) => setKeyUse(e.target.value)}
            style={commonInputStyle}
          >
            {getAvailableKeyUses().map(opt => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Key Operations Section */}
      <div style={{ marginBottom: 20 }}>
        <label style={commonLabelStyle}>Key Operations (key_ops) - Optional</label>
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

      {/* Generate Button */}
      <button
        onClick={handleGenerate}
        disabled={isLoading}
        style={{ 
          background: isLoading ? "#6c757d" : "rgb(11, 99, 233)", 
          color: "#fff", 
          border: "none", 
          borderRadius: 4, 
          padding: "10px 20px", 
          fontWeight: 600, 
          fontSize: 14, 
          cursor: isLoading ? "not-allowed" : "pointer",
          fontFamily: "Inter, sans-serif",
          transition: "background-color 0.2s"
        }}
      >
        {isLoading ? "Generating..." : "Generate Key"}
      </button>

      {/* Error Display */}
      {error && (
        <div style={{ 
          color: "#721c24", 
          marginTop: 16, 
          padding: "12px",
          background: "#f8d7da",
          border: "1px solid #f5c6cb",
          borderRadius: 4,
          fontSize: 14,
          fontFamily: "Inter, sans-serif"
        }}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* Results Section */}
      {(generatedJWK || generatedPublicKey || generatedPrivateKey) && (
        <div style={{ marginTop: 24 }}>
          {/* JWK Output */}
          <div style={{ marginBottom: 20 }}>
            <label style={commonLabelStyle}>JWK (JSON Web Key)</label>
            <pre
              style={{
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
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
                textAlign: "left",
                overflow: "auto"
              }}
            >
              {generatedJWK}
            </pre>
          </div>

          {/* Public Key Output */}
          <div style={{ marginBottom: 20 }}>
            <label style={commonLabelStyle}>PKIX Public Key (PEM)</label>
            <pre
              style={{
                background: "#f8f9fa",
                padding: 16,
                borderRadius: 4,
                fontSize: 14,
                marginTop: 6,
                border: "1px solid #e9ecef",
                fontFamily: "monospace",
                lineHeight: 1.5,
                color: "#495057",
                minHeight: "80px",
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
                textAlign: "left",
                overflow: "auto"
              }}
            >
              {generatedPublicKey}
            </pre>
          </div>

          {/* Private Key Output */}
          <div style={{ marginBottom: 20 }}>
            <label style={commonLabelStyle}>PKCS #8 Private Key (PEM)</label>
            <pre
              style={{
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
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
                textAlign: "left",
                overflow: "auto"
              }}
            >
              {generatedPrivateKey}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};

export default GenerateNewKey; 