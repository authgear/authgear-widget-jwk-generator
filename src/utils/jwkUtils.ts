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

// Generate fingerprint from PEM (SHA-256 hash of the key)
export async function generateFingerprint(pem: string): Promise<string> {
  try {
    // Remove PEM headers/footers and whitespace
    const cleanPem = pem.replace(/-----BEGIN.*-----|-----END.*-----/g, '').replace(/\s/g, '');
    const keyBuffer = Uint8Array.from(atob(cleanPem), c => c.charCodeAt(0));
    
    // Generate SHA-256 hash
    const hashBuffer = await crypto.subtle.digest('SHA-256', keyBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const fingerprint = hashArray.map(b => b.toString(16).padStart(2, '0')).join(':').toUpperCase();
    
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
    // Handle key_ops - remove if none selected, add if operations are selected
    if (key_ops && key_ops.length > 0) {
      jwk.key_ops = key_ops;
    } else {
      // Remove key_ops if it was automatically added by jose library
      delete jwk.key_ops;
    }
    
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
  const algorithms = ['RS256', 'ES256', 'PS256'];
  
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
  const algorithms = ['RS256', 'ES256', 'PS256'];
  
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
    return 'EdDSA';
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
export async function jwkToPem(jwk: JsonWebKey): Promise<string> {
  try {
    debug('Converting JWK to PEM:', jwk);
    
    // Validate JWK first
    const validation = validateJWK(jwk);
    if (!validation.isValid) {
      throw new Error(`Invalid JWK: ${validation.errors.join(', ')}`);
    }
    
    let key: CryptoKey;
    let keyType: 'public' | 'private';
    
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
    if (keyType === 'public') {
      key = await crypto.subtle.importKey(
        'jwk',
        jwk,
        getAlgorithmFromJWK(jwk),
        true,
        ['verify']
      );
    } else {
      key = await crypto.subtle.importKey(
        'jwk',
        jwk,
        getAlgorithmFromJWK(jwk),
        true,
        ['sign']
      );
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
    
    return `${pemHeader}\n${formatted}\n${pemFooter}`;
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
    return {
      name: 'Ed25519'
    };
  }
  throw new Error(`Unsupported key type: ${jwk.kty}`);
} 