import * as jose from 'jose';

// Debug utility that only logs in development mode
const debug = (...args: any[]) => {
  if (import.meta.env.DEV) {
    console.log(...args);
  }
};

interface JWKOptions {
  keyId?: string;
  alg?: string;
  use?: string;
  key_ops?: string[];
}

type KeyType = 'public' | 'private' | 'rsa-private' | 'certificate' | 'ec-private' | 'unknown';

// Generate fingerprint from PEM (SHA-256 hash of the key) - SSH-style base64 format
export async function generateFingerprint(pem: string): Promise<string> {
  try {
    // Remove PEM headers/footers and whitespace
    const cleanPem = pem.replace(/-----BEGIN.*-----|-----END.*-----/g, '').replace(/\s/g, '');
    const keyBuffer = Uint8Array.from(atob(cleanPem), c => c.charCodeAt(0));
    
    // Generate SHA-256 hash
    const hashBuffer = await crypto.subtle.digest('SHA-256', keyBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    // Convert to base64 format like SSH-keygen SHA256 fingerprint
    const fingerprint = btoa(String.fromCharCode(...hashArray));
    
    return fingerprint;
  } catch (error) {
    throw new Error('Failed to generate fingerprint: ' + (error instanceof Error ? error.message : 'Unknown error'));
  }
}

// Detect key type from PEM
export function detectKeyType(pem: string): KeyType {
  if (pem.includes('-----BEGIN PUBLIC KEY-----')) {
    return 'public';
  } else if (pem.includes('-----BEGIN PRIVATE KEY-----')) {
    return 'private';
  } else if (pem.includes('-----BEGIN RSA PRIVATE KEY-----')) {
    return 'rsa-private';
  } else if (pem.includes('-----BEGIN CERTIFICATE-----')) {
    return 'certificate';
  } else if (pem.includes('-----BEGIN EC PRIVATE KEY-----')) {
    return 'ec-private';
  }
  return 'unknown';
}

// Convert PEM to JWK using a simplified approach
export async function pemToJwk(pem: string, options: JWKOptions = {}): Promise<JsonWebKey> {
  try {
    const { keyId, alg, use, key_ops } = options;
    const keyType = detectKeyType(pem);
    
    debug('Converting PEM to JWK:', { keyType, alg, use });
    
    let jwk: JsonWebKey & { kid?: string; alg?: string; use?: string };
    
    if (keyType === 'certificate') {
      debug('Processing certificate...');
      const key = await jose.importX509(pem, alg || 'RS256');
      jwk = await jose.exportJWK(key);
    } else if (keyType === 'public') {
      debug('Processing public key...');
      jwk = await convertPublicKeyToJwk(pem, alg);
    } else if (keyType === 'private' || keyType === 'rsa-private' || keyType === 'ec-private') {
      debug('Processing private key...');
      jwk = await convertPrivateKeyToJwk(pem, alg);
    } else {
      throw new Error('Unsupported key type. Please ensure the PEM format is correct.');
    }
    
    debug('Generated JWK:', jwk);
    
    // Add optional fields
    if (keyId) {
      jwk.kid = keyId;
    }
    if (alg) {
      jwk.alg = alg;
    }
    if (use) {
      jwk.use = use;
    }
    // Handle key_ops - only add if explicitly provided, don't override existing ones
    if (key_ops && key_ops.length > 0) {
      jwk.key_ops = key_ops;
    }
    // Note: We don't delete existing key_ops to preserve original claims
    
    return jwk;
  } catch (error) {
    console.error('PEM to JWK conversion error:', error);
    throw new Error('Failed to convert PEM to JWK: ' + (error instanceof Error ? error.message : 'Unknown error'));
  }
}

// Convert public key to JWK - using raw Web Crypto API to ensure extractable keys
async function convertPublicKeyToJwk(pem: string, specifiedAlg?: string) {
  debug('convertPublicKeyToJwk called with alg:', specifiedAlg);
  
  // Clean the PEM
  const cleanPem = pem.replace(/-----BEGIN.*-----|-----END.*-----/g, '').replace(/\s/g, '');
  const keyBuffer = Uint8Array.from(atob(cleanPem), c => c.charCodeAt(0));
  
  // Try the specified algorithm first
  if (specifiedAlg) {
    try {
      debug(`Trying specified algorithm: ${specifiedAlg}`);
      const key = await crypto.subtle.importKey(
        'spki',
        keyBuffer,
        getAlgorithmObject(specifiedAlg),
        true, // extractable
        ['verify']
      );
      const jwk = await crypto.subtle.exportKey('jwk', key);
      debug(`Success with ${specifiedAlg}:`, jwk);
      return jwk;
    } catch (e) {
      debug(`Failed with specified algorithm ${specifiedAlg}:`, e instanceof Error ? e.message : 'Unknown error');
    }
  }
  
  // Try common algorithms in order
  const algorithms = ['RS256', 'ES256', 'PS256', 'ECDH-ES'];
  
  for (const algorithm of algorithms) {
    try {
      debug(`Trying algorithm: ${algorithm}`);
      const key = await crypto.subtle.importKey(
        'spki',
        keyBuffer,
        getAlgorithmObject(algorithm),
        true, // extractable
        ['verify']
      );
      const jwk = await crypto.subtle.exportKey('jwk', key);
      debug(`Success with ${algorithm}:`, jwk);
      return jwk;
    } catch (e) {
      debug(`Failed with ${algorithm}:`, e instanceof Error ? e.message : 'Unknown error');
      continue;
    }
  }
  
  throw new Error('Could not convert public key to JWK with any supported algorithm.');
}

// Convert private key to JWK - using raw Web Crypto API to ensure extractable keys
async function convertPrivateKeyToJwk(pem: string, specifiedAlg?: string) {
  debug('convertPrivateKeyToJwk called with alg:', specifiedAlg);
  
  // Clean the PEM
  const cleanPem = pem.replace(/-----BEGIN.*-----|-----END.*-----/g, '').replace(/\s/g, '');
  const keyBuffer = Uint8Array.from(atob(cleanPem), c => c.charCodeAt(0));
  
  // Try the specified algorithm first
  if (specifiedAlg) {
    try {
      debug(`Trying specified algorithm: ${specifiedAlg}`);
      const key = await crypto.subtle.importKey(
        'pkcs8',
        keyBuffer,
        getAlgorithmObject(specifiedAlg),
        true, // extractable
        ['sign']
      );
      const jwk = await crypto.subtle.exportKey('jwk', key);
      debug(`Success with ${specifiedAlg}:`, jwk);
      return jwk;
    } catch (e) {
      debug(`Failed with specified algorithm ${specifiedAlg}:`, e instanceof Error ? e.message : 'Unknown error');
    }
  }
  
  // Try common algorithms in order
  const algorithms = ['RS256', 'ES256', 'PS256', 'ECDH-ES'];
  
  for (const algorithm of algorithms) {
    try {
      debug(`Trying algorithm: ${algorithm}`);
      const key = await crypto.subtle.importKey(
        'pkcs8',
        keyBuffer,
        getAlgorithmObject(algorithm),
        true, // extractable
        ['sign']
      );
      const jwk = await crypto.subtle.exportKey('jwk', key);
      debug(`Success with ${algorithm}:`, jwk);
      return jwk;
    } catch (e) {
      debug(`Failed with ${algorithm}:`, e instanceof Error ? e.message : 'Unknown error');
      continue;
    }
  }
  
  throw new Error('Could not convert private key to JWK with any supported algorithm.');
}

// Helper function to get algorithm object for Web Crypto API
function getAlgorithmObject(algorithm: string | undefined) {
  if (!algorithm) {
    throw new Error('No algorithm specified');
  }
  switch (algorithm) {
    case 'RS256':
    case 'RS384':
    case 'RS512':
      return {
        name: 'RSASSA-PKCS1-v1_5',
        hash: { name: algorithm.replace('RS', 'SHA-') }
      };
    case 'PS256':
    case 'PS384':
    case 'PS512':
      return {
        name: 'RSA-PSS',
        hash: { name: algorithm.replace('PS', 'SHA-') }
      };
    case 'ES256':
      return {
        name: 'ECDSA',
        namedCurve: 'P-256'
      };
    case 'ES384':
      return {
        name: 'ECDSA',
        namedCurve: 'P-384'
      };
    case 'ES512':
      return {
        name: 'ECDSA',
        namedCurve: 'P-521'
      };
    case 'ECDH-ES':
      return {
        name: 'ECDH',
        namedCurve: 'P-256'
      };
    default:
      throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
}

// Auto-detect algorithm from key type (for reference)
export function detectAlgorithm(jwk: JsonWebKey) {
  if (jwk.kty === 'RSA') {
    return 'RS256';
  } else if (jwk.kty === 'EC') {
    if (jwk.crv === 'P-256') {
      return 'ES256';
    } else if (jwk.crv === 'P-384') {
      return 'ES384';
    } else if (jwk.crv === 'P-521') {
      return 'ES512';
    }
  } else if (jwk.kty === 'OKP') {
    if (jwk.crv === 'Ed25519') {
      return 'EdDSA';
    } else if (jwk.crv === 'X25519') {
      return 'ECDH-ES';
    }
  }
  return null;
}

// Validate JWK structure and required fields
export function validateJWK(jwk: any): { isValid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (!jwk || typeof jwk !== 'object') {
    errors.push('JWK must be a valid JSON object');
    return { isValid: false, errors };
  }
  
  // Check required fields
  if (!jwk.kty) {
    errors.push('Missing required field: kty (key type)');
  }
  
  if (!jwk.kid) {
    errors.push('Missing required field: kid (key ID)');
  }
  
  // Validate key type specific fields
  if (jwk.kty === 'RSA') {
    if (!jwk.n) errors.push('RSA key missing required field: n (modulus)');
    if (!jwk.e) errors.push('RSA key missing required field: e (exponent)');
  } else if (jwk.kty === 'EC') {
    if (!jwk.crv) errors.push('EC key missing required field: crv (curve)');
    if (!jwk.x) errors.push('EC key missing required field: x (x coordinate)');
    if (!jwk.y) errors.push('EC key missing required field: y (y coordinate)');
  } else if (jwk.kty === 'OKP') {
    if (!jwk.crv) errors.push('OKP key missing required field: crv (curve)');
    if (!jwk.x) errors.push('OKP key missing required field: x (public key)');
  } else {
    errors.push(`Unsupported key type: ${jwk.kty}`);
  }
  
  return { isValid: errors.length === 0, errors };
}

// Convert JWK to PEM
export async function jwkToPem(jwk: JsonWebKey): Promise<{ pem: string; warnings: string[] }> {
  try {
    debug('Converting JWK to PEM:', jwk);
    
    // Validate JWK first
    const validation = validateJWK(jwk);
    if (!validation.isValid) {
      throw new Error(`Invalid JWK: ${validation.errors.join(', ')}`);
    }
    
    let key: CryptoKey;
    let keyType: 'public' | 'private';
    const warnings: string[] = [];
    
    // Determine if this is a public or private key
    if (jwk.kty === 'RSA') {
      keyType = jwk.d ? 'private' : 'public';
    } else if (jwk.kty === 'EC') {
      keyType = jwk.d ? 'private' : 'public';
    } else if (jwk.kty === 'OKP') {
      keyType = jwk.d ? 'private' : 'public';
    } else {
      throw new Error(`Unsupported key type: ${jwk.kty}`);
    }
    
    // Import the JWK
    const algorithm = getAlgorithmFromJWK(jwk);
    let keyUsages: KeyUsage[];
    
    // Extract key usages from JWK's key_ops if present, otherwise use defaults
    if (jwk.key_ops && jwk.key_ops.length > 0) {
      // Map JWK key_ops to Web Crypto KeyUsage
      const jwkUsages = new Set(jwk.key_ops);
      const webCryptoUsages: KeyUsage[] = [];
      
      // Map JWK operations to Web Crypto usages
      if (jwkUsages.has('sign')) webCryptoUsages.push('sign');
      if (jwkUsages.has('verify')) webCryptoUsages.push('verify');
      if (jwkUsages.has('encrypt')) webCryptoUsages.push('encrypt');
      if (jwkUsages.has('decrypt')) webCryptoUsages.push('decrypt');
      if (jwkUsages.has('wrapKey')) webCryptoUsages.push('wrapKey');
      if (jwkUsages.has('unwrapKey')) webCryptoUsages.push('unwrapKey');
      if (jwkUsages.has('deriveKey')) webCryptoUsages.push('deriveKey');
      if (jwkUsages.has('deriveBits')) webCryptoUsages.push('deriveBits');
      
      // Validate that we have appropriate usages for the key type
      if (keyType === 'public') {
        if (webCryptoUsages.includes('verify')) {
          keyUsages = ['verify'];
        } else if (webCryptoUsages.includes('encrypt')) {
          keyUsages = ['encrypt'];
        } else if (webCryptoUsages.includes('wrapKey')) {
          keyUsages = ['wrapKey'];
        } else {
          // Fallback to verify for public keys
          keyUsages = ['verify'];
          warnings.push(`JWK key_ops "${jwk.key_ops.join(', ')}" not suitable for public key, using 'verify' instead`);
        }
      } else {
        if (webCryptoUsages.includes('sign')) {
          keyUsages = ['sign'];
        } else if (webCryptoUsages.includes('decrypt')) {
          keyUsages = ['decrypt'];
        } else if (webCryptoUsages.includes('unwrapKey')) {
          keyUsages = ['unwrapKey'];
        } else {
          // Fallback to sign for private keys
          keyUsages = ['sign'];
          warnings.push(`JWK key_ops "${jwk.key_ops.join(', ')}" not suitable for private key, using 'sign' instead`);
        }
      }
      
      // Add warning if key_ops doesn't match the key type
      if (keyType === 'public' && jwk.key_ops.includes('sign')) {
        warnings.push(`Public key has 'sign' in key_ops, but public keys cannot sign. This field will be ignored.`);
      } else if (keyType === 'private' && jwk.key_ops.includes('verify')) {
        warnings.push(`Private key has 'verify' in key_ops, but private keys cannot verify. This field will be ignored.`);
      }
    } else {
      // Use default usages based on key type
      if (algorithm.name === 'ECDH') {
        keyUsages = ['deriveKey', 'deriveBits'];
      } else {
        keyUsages = keyType === 'public' ? ['verify'] : ['sign'];
      }
    }
    
    // Add warnings for other optional fields that might cause issues
    if (jwk.alg && jwk.alg !== 'RS256' && jwk.alg !== 'ES256' && jwk.alg !== 'PS256') {
      warnings.push(`Algorithm '${jwk.alg}' specified in JWK, but using default algorithm for conversion`);
    }
    
    if (jwk.use && jwk.use !== 'sig' && jwk.use !== 'enc') {
      warnings.push(`Key use '${jwk.use}' specified in JWK, but this field is not used in PEM conversion`);
    }
    
    try {
      if (keyType === 'public') {
        key = await crypto.subtle.importKey(
          'jwk',
          jwk,
          algorithm,
          true,
          keyUsages
        );
      } else {
        key = await crypto.subtle.importKey(
          'jwk',
          jwk,
          algorithm,
          true,
          keyUsages
        );
      }
    } catch (importError) {
      // If import fails due to key_ops conflict, try with default key usages
      if (importError instanceof Error && importError.message.includes('key_ops')) {
        warnings.push(`JWK key_ops conflict detected, retrying with default key usages`);
        
        // Create a modified JWK without key_ops for the fallback attempt
        const fallbackJwk = { ...jwk };
        delete fallbackJwk.key_ops;
        
        // Use default usages that are guaranteed to work
        let fallbackUsages: KeyUsage[];
        if (algorithm.name === 'ECDH') {
          fallbackUsages = ['deriveKey', 'deriveBits'];
        } else {
          fallbackUsages = keyType === 'public' ? ['verify'] : ['sign'];
        }
        
        key = await crypto.subtle.importKey(
          'jwk',
          fallbackJwk,
          algorithm,
          true,
          fallbackUsages
        );
      } else {
        throw importError;
      }
    }
    
    // Export as PEM
    const format = keyType === 'public' ? 'spki' : 'pkcs8';
    const exported = await crypto.subtle.exportKey(format, key);
    
    // Convert to base64 and format as PEM
    const base64 = btoa(String.fromCharCode(...new Uint8Array(exported)));
    const pemHeader = keyType === 'public' ? '-----BEGIN PUBLIC KEY-----' : '-----BEGIN PRIVATE KEY-----';
    const pemFooter = keyType === 'public' ? '-----END PUBLIC KEY-----' : '-----END PRIVATE KEY-----';
    
    // Format with line breaks every 64 characters
    const formatted = base64.match(/.{1,64}/g)?.join('\n') || base64;
    
    const pem = `${pemHeader}\n${formatted}\n${pemFooter}`;
    
    return { pem, warnings };
  } catch (error) {
    console.error('JWK to PEM conversion error:', error);
    throw new Error('Failed to convert JWK to PEM: ' + (error instanceof Error ? error.message : 'Unknown error'));
  }
}

// Helper function to get algorithm object from JWK
function getAlgorithmFromJWK(jwk: JsonWebKey) {
  if (jwk.kty === 'RSA') {
    return {
      name: 'RSASSA-PKCS1-v1_5',
      hash: { name: 'SHA-256' }
    };
  } else if (jwk.kty === 'EC') {
    return {
      name: 'ECDSA',
      namedCurve: jwk.crv || 'P-256'
    };
  } else if (jwk.kty === 'OKP') {
    if (jwk.crv === 'Ed25519') {
      return {
        name: 'Ed25519'
      };
    } else if (jwk.crv === 'X25519') {
      return {
        name: 'ECDH',
        namedCurve: 'P-256'
      };
    }
  }
  throw new Error(`Unsupported key type: ${jwk.kty}`);
} 