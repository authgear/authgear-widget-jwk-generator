import React, { useState, useEffect, useRef } from "react";
import { jwkToPem, validateJWK } from "../utils/jwkUtils";

type JWKInput = JsonWebKey;

const JWKToPEM: React.FC = () => {
  const [jwkInput, setJwkInput] = useState<string>("");
  const [pem, setPem] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [highlighted, setHighlighted] = useState<string>("");
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [copySuccess, setCopySuccess] = useState<boolean>(false);
  const preRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    if (pem) {
      setHighlighted(pem);
    } else {
      setHighlighted("");
    }
  }, [pem]);

  const handleConvert = async (): Promise<void> => {
    if (!jwkInput.trim()) {
      setError("Please enter a JWK (JSON Web Key)");
      setPem("");
      setValidationErrors([]);
      return;
    }

    setIsLoading(true);
    setError("");
    setPem("");
    setValidationErrors([]);
    setWarnings([]);

    try {
      // Parse JSON input
      let jwk: JWKInput;
      try {
        jwk = JSON.parse(jwkInput);
      } catch (parseError) {
        throw new Error("Invalid JSON format. Please check your JWK input.");
      }

      // Validate JWK structure
      const validation = validateJWK(jwk);
      if (!validation.isValid) {
        setValidationErrors(validation.errors);
        throw new Error("JWK validation failed. Please check the errors below.");
      }

      // Convert JWK to PEM
      const result = await jwkToPem(jwk);
      setPem(result.pem);
      setWarnings(result.warnings);
    } catch (err) {
      console.error("JWK to PEM error:", err);
      setError(err instanceof Error ? err.message : "An unknown error occurred");
      setPem("");
      setWarnings([]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopyToClipboard = async (): Promise<void> => {
    if (pem) {
      try {
        await navigator.clipboard.writeText(pem);
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
      {/* JWK Input Section */}
      <div style={{ marginBottom: 16 }}>
        <label style={commonLabelStyle}>JWK (JSON Web Key)</label>
        <textarea
          value={jwkInput}
          onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setJwkInput(e.target.value)}
          rows={12}
          style={{
            ...commonInputStyle,
            fontFamily: "monospace",
            resize: "vertical",
            minHeight: "180px",
            lineHeight: "1.4"
          }}
          placeholder={`{
  "kty": "RSA",
  "kid": "example-key-id",
  "n": "modulus-value",
  "e": "exponent-value"
}`}
        />
      </div>

      {/* Convert Button */}
      <button
        onClick={handleConvert}
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
        {isLoading ? "Converting..." : "Convert to PEM"}
      </button>

      {/* Validation Errors Display */}
      {validationErrors.length > 0 && (
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
          <strong>Validation Errors:</strong>
          <ul style={{ margin: "8px 0 0 20px", padding: 0 }}>
            {validationErrors.map((error, index) => (
              <li key={index}>{error}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Warnings Display */}
      {warnings.length > 0 && (
        <div style={{ 
          color: "#856404", 
          marginTop: 16, 
          padding: "12px",
          background: "#fff3cd",
          border: "1px solid #ffeaa7",
          borderRadius: 4,
          fontSize: 14,
          fontFamily: "Inter, sans-serif"
        }}>
          <strong>⚠️ Conversion Warnings:</strong>
          <ul style={{ margin: "8px 0 0 20px", padding: 0 }}>
            {warnings.map((warning, index) => (
              <li key={index}>{warning}</li>
            ))}
          </ul>
          <p style={{ margin: "8px 0 0 0", fontSize: "13px", fontStyle: "italic" }}>
            Conversion completed successfully, but some optional fields were adjusted or ignored.
          </p>
        </div>
      )}

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

      {/* PEM Output */}
      <div style={{ marginTop: 24 }}>
        <label style={commonLabelStyle}>PEM Output</label>
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
          >
            {highlighted || (
              <span style={{ color: "#6c757d", fontStyle: "italic" }}>
                Enter a JWK and click "Convert to PEM" to see the output
              </span>
            )}
          </pre>
          {pem && (
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

      {/* Help Section */}
      <div style={{ 
        marginTop: 24, 
        padding: "16px",
        background: "#e3f2fd",
        border: "1px solid #bbdefb",
        borderRadius: 4,
        fontSize: 14,
        fontFamily: "Inter, sans-serif"
      }}>
        <strong>JWK Format Help:</strong>
        <ul style={{ margin: "8px 0 0 20px", padding: 0 }}>
          <li><strong>RSA Keys:</strong> Require <code>kty</code>, <code>kid</code>, <code>n</code> (modulus), and <code>e</code> (exponent)</li>
          <li><strong>EC Keys:</strong> Require <code>kty</code>, <code>kid</code>, <code>crv</code> (curve), <code>x</code>, and <code>y</code> coordinates</li>
          <li><strong>OKP Keys:</strong> Require <code>kty</code>, <code>kid</code>, <code>crv</code> (curve), and <code>x</code> (public key)</li>
          <li>Private keys include additional fields like <code>d</code> (private key component)</li>
        </ul>
      </div>
    </div>
  );
};

export default JWKToPEM;
