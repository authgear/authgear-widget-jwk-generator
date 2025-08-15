import React, { useState, useEffect, useRef } from "react";
import { pemToJwk, generateFingerprint, detectKeyType } from "../utils/jwkUtils";
import Prism from "prismjs";
import "prismjs/components/prism-json";
import "prismjs/themes/prism.css";

interface KeyAlgorithm {
  value: string;
  label: string;
}

interface KeyUse {
  value: string;
  label: string;
}



type JWKResult = JsonWebKey;

const KEY_ALGORITHMS: KeyAlgorithm[] = [
  { value: "", label: "(unspecified)" },
  { value: "RS256", label: "RS256 (RSA)" },
  { value: "RS384", label: "RS384 (RSA)" },
  { value: "RS512", label: "RS512 (RSA)" },
  { value: "PS256", label: "PS256 (RSA-PSS)" },
  { value: "PS384", label: "PS384 (RSA-PSS)" },
  { value: "PS512", label: "PS512 (RSA-PSS)" },
  { value: "ES256", label: "ES256 (ECDSA)" },
  { value: "ES384", label: "ES384 (ECDSA)" },
  { value: "ES512", label: "ES512 (ECDSA)" },
  { value: "EdDSA", label: "EdDSA (Ed25519)" },
];

const KEY_USES: KeyUse[] = [
  { value: "", label: "(unspecified)" },
  { value: "sig", label: "Signature" },
  { value: "enc", label: "Encryption" },
];



const PEMToJWK: React.FC = () => {
  const [pem, setPem] = useState<string>("");
  const [keyId, setKeyId] = useState<string>("");
  const [alg, setAlg] = useState<string>("");
  const [use, setUse] = useState<string>("");

  const [jwk, setJwk] = useState<JWKResult | null>(null);
  const [error, setError] = useState<string>("");
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [highlighted, setHighlighted] = useState<string>("");
  const [copySuccess, setCopySuccess] = useState<boolean>(false);
  const preRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    if (jwk) {
      const json = JSON.stringify(jwk, null, 2);
      const jsonGrammar = Prism.languages['json'];
      if (jsonGrammar) {
        setHighlighted(Prism.highlight(json, jsonGrammar, "json"));
      } else {
        setHighlighted(json);
      }
    } else {
      setHighlighted("");
    }
  }, [jwk]);



  const handleGenerate = async (): Promise<void> => {
    if (!pem.trim()) {
      setError("Please enter a PEM encoded key or certificate");
      setJwk(null);
      return;
    }

    setIsLoading(true);
    setError("");
    setJwk(null);

    try {
      // Detect key type for validation
      const keyType = detectKeyType(pem);
      if (keyType === 'unknown') {
        throw new Error("Unable to detect key type. Please ensure the PEM format is correct.");
      }

      // Generate fingerprint if keyId is empty
      let finalKeyId = keyId;
      if (!keyId.trim()) {
        finalKeyId = await generateFingerprint(pem);
      }

      // Convert PEM to JWK - only pass alg if it's explicitly set
      const options: { keyId: string; alg?: string; use?: string; key_ops?: string[] } = {
        keyId: finalKeyId,
      };
      if (alg.trim()) {
        options.alg = alg.trim();
      }
      if (use.trim()) {
        options.use = use.trim();
      }

      const result = await pemToJwk(pem, options);

      setJwk(result);
    } catch (err) {
      console.error("PEM to JWK error:", err);
      setError(err instanceof Error ? err.message : "An unknown error occurred");
      setJwk(null);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopyToClipboard = async (): Promise<void> => {
    if (jwk) {
      try {
        const jsonString = JSON.stringify(jwk, null, 2);
        await navigator.clipboard.writeText(jsonString);
        setCopySuccess(true);
        setTimeout(() => setCopySuccess(false), 2000);
      } catch (err) {
        console.error("Failed to copy to clipboard:", err);
      }
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
    <div style={{ fontFamily: "Inter, sans-serif", color: "#495057", padding: "16px", width: "100%", height: "100%", boxSizing: "border-box", overflow: "auto" }}>
      {/* PEM Input Section */}
      <div style={{ marginBottom: 16 }}>
        <label style={commonLabelStyle}>PEM encoded key or certificate</label>
        <textarea
          value={pem}
          onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setPem(e.target.value)}
          rows={8}
          style={{
            ...commonInputStyle,
            fontFamily: "monospace",
            resize: "vertical",
            minHeight: "120px",
            lineHeight: "1.4"
          }}
          placeholder={"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"}
        />
      </div>
      {/* Key Metadata Section */}
      <div 
        className="responsive-grid"
        style={{ 
          display: "grid", 
          gridTemplateColumns: "1fr 1fr 1fr", 
          gap: 16, 
          marginBottom: 16,
          width: "100%",
          boxSizing: "border-box"
        }}
      >
        <div>
          <label style={commonLabelStyle}>Key ID (kid)</label>
          <input
            type="text"
            value={keyId}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setKeyId(e.target.value)}
            style={commonInputStyle}
            placeholder="Leave empty to use SHA256 fingerprint of PEM as Key ID"
          />
        </div>
        <div>
          <label style={commonLabelStyle}>Key Algorithm (alg)</label>
          <select
            value={alg}
            onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setAlg(e.target.value)}
            style={commonInputStyle}
          >
            {KEY_ALGORITHMS.map(opt => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>
        <div>
          <label style={commonLabelStyle}>Key Use (use)</label>
          <select
            value={use}
            onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setUse(e.target.value)}
            style={commonInputStyle}
          >
            {KEY_USES.map(opt => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>
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
        {isLoading ? "Generating..." : "Generate JWK"}
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
      {/* JWK Output - Always visible like in the reference */}
      <div style={{ marginTop: 24 }}>
        <label style={commonLabelStyle}>JWK (JSON Web Key)</label>
        <div style={{ position: "relative" }}>
          <pre
            ref={preRef}
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
            dangerouslySetInnerHTML={{
              __html: highlighted ||
                '<span style="color: #6c757d; font-style: italic;">Enter a PEM key and click "Generate JWK" to see the output</span>'
            }}
          />
          {jwk && (
            <button
              onClick={handleCopyToClipboard}
              style={{
                position: "absolute",
                top: "10px",
                right: "10px",
                background: copySuccess ? "#28a745" : "#6c757d",
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
              {copySuccess ? "COPIED!" : "COPY"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default PEMToJWK;
