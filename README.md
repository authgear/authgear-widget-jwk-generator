# Authgear JWK Generator Widget

A web-based tool for converting between PEM-formatted keys and JSON Web Keys (JWK) format, specifically designed for Authgear integration.

## Features

- **PEM to JWK Conversion**: Convert PEM-encoded keys and certificates to JWK format
- **Key Fingerprint Generation**: Generate SHA-256 fingerprints for keys
- **Multiple Key Types**: Support for RSA, ECDSA, EdDSA, and X25519 keys
- **Customizable Metadata**: Add key ID, algorithm, usage, and operations
- **Syntax Highlighting**: JSON output with syntax highlighting

## Quick Start

1. **Install dependencies**:
   ```bash
   npm install
   ```

2. **Start development server**:
   ```bash
   npm run dev
   ```

3. **Build for production**:
   ```bash
   npm run build
   ```

## Usage

1. Open the application in your browser
2. Select "PEM to JWK" tab
3. Paste your PEM-encoded key or certificate
4. Optionally configure:
   - Key ID (kid)
   - Algorithm (alg)
   - Key usage (use)
   - Key operations (key_ops)
5. Click "Generate JWK" to convert

## Supported Formats

- **Public Keys**
- **Private Keys**
- **RSA Private Keys**
- **EC Private Keys**
- **Certificates**

## Supported Key Types

- **RSA**: Digital signatures and encryption (RS256, RS384, RS512)
- **ECDSA**: Digital signatures (ES256, ES384, ES512)
- **Ed25519**: Modern digital signatures (EdDSA)
- **X25519**: Key exchange and encryption (ECDH-ES)

## Technologies

- React 18
- TypeScript
- Vite
- jose (JWT/WebCrypto library)
- Prism.js (syntax highlighting)

## Development

```bash
npm run type-check  # Type checking
npm run preview     # Preview production build
``` 