const crypto = require('crypto');

const MAX_TIMESTAMP_SKEW_SEC = 300; // 5 minutes replay protection window
const MASTER_VAULT_KEY = crypto.createHash('sha256')
  .update(process.env.AGENT_VAULT_SECRET || process.env.GATEWAY_SHARED_SECRET || 'secguard_master_vault_key_2026')
  .digest(); // 32 bytes for AES-256

/**
 * Encrypts a string using AES-256-GCM
 */
function encryptSecret(plaintext) {
  if (!plaintext) return null;
  const iv = crypto.randomBytes(12); // standard 96-bit IV for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_VAULT_KEY, iv);
  let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
  ciphertext += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${tag}:${ciphertext}`;
}

/**
 * Decrypts an AES-256-GCM encrypted secret string
 */
function decryptSecret(encryptedPayload) {
  if (!encryptedPayload || typeof encryptedPayload !== 'string') return null;
  const parts = encryptedPayload.split(':');
  if (parts.length !== 3) return null;
  const [ivHex, tagHex, ciphertextHex] = parts;
  try {
    const iv = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', MASTER_VAULT_KEY, iv);
    decipher.setAuthTag(tag);
    let decrypted = decipher.update(ciphertextHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    return null;
  }
}

/**
 * Computes SHA-256 hash of a secret string
 * @param {string} secret 
 * @returns {string} 64-char hex hash
 */
function hashSecret(secret) {
  if (!secret || typeof secret !== 'string') return '';
  return crypto.createHash('sha256').update(secret).digest('hex');
}

/**
 * Generates a cryptographically strong agent secret, its SHA-256 hash, and AES-256-GCM encrypted envelope
 * @returns {{ plaintextSecret: string, secretHash: string, encryptedSecret: string }}
 */
function generateAgentSecret() {
  const token = crypto.randomBytes(24).toString('hex');
  const plaintextSecret = `secguard_ag_${token}`;
  const secretHash = hashSecret(plaintextSecret);
  const encryptedSecret = encryptSecret(plaintextSecret);
  return { plaintextSecret, secretHash, encryptedSecret };
}

/**
 * Timing-safe string comparison
 */
function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Computes HMAC-SHA256 signature for payload with timestamp
 * @param {string|object} body - Raw string payload or JSON object
 * @param {number|string} timestamp - Unix timestamp in seconds
 * @param {string} secret - Plaintext secret key
 * @returns {string} Hex HMAC signature
 */
function signPayload(body, timestamp, secret) {
  if (!secret || typeof secret !== 'string') return '';
  const content = typeof body === 'string' ? body : JSON.stringify(body);
  const payloadToSign = `${timestamp}.${content}`;
  return crypto.createHmac('sha256', secret).update(payloadToSign).digest('hex');
}

/**
 * Verifies HMAC signature header against raw body and secret
 * 
 * Header syntax: "t=<timestamp_sec>,v1=<hex_signature>"
 * 
 * @param {string|object} body - Request body
 * @param {string} signatureHeader - Value of X-Agent-Signature header
 * @param {string} secret - Plaintext secret
 * @returns {{ valid: boolean, error?: string, timestamp?: number }}
 */
function verifyHmacSignature(body, signatureHeader, secret) {
  if (!signatureHeader || typeof signatureHeader !== 'string') {
    return { valid: false, error: 'Missing X-Agent-Signature header' };
  }

  // Parse t=... and v1=...
  const parts = signatureHeader.split(',').reduce((acc, part) => {
    const [k, v] = part.split('=');
    if (k && v) acc[k.trim()] = v.trim();
    return acc;
  }, {});

  const timestampStr = parts.t;
  const signature = parts.v1;

  if (!timestampStr || !signature) {
    return { valid: false, error: 'Malformed X-Agent-Signature format. Expected: t=<timestamp>,v1=<signature>' };
  }

  const timestamp = parseInt(timestampStr, 10);
  if (isNaN(timestamp)) {
    return { valid: false, error: 'Invalid timestamp in signature' };
  }

  // Check replay / clock skew (in seconds)
  const now = Math.floor(Date.now() / 1000);
  const skew = Math.abs(now - timestamp);
  if (skew > MAX_TIMESTAMP_SKEW_SEC) {
    return { 
      valid: false, 
      error: `Signature expired or replay detected. Clock skew of ${skew}s exceeds ${MAX_TIMESTAMP_SKEW_SEC}s threshold.` 
    };
  }

  // Verify HMAC
  const expectedSig = signPayload(body, timestamp, secret);
  if (!safeCompare(signature, expectedSig)) {
    return { valid: false, error: 'Invalid HMAC signature' };
  }

  return { valid: true, timestamp };
}

module.exports = {
  generateAgentSecret,
  hashSecret,
  encryptSecret,
  decryptSecret,
  safeCompare,
  signPayload,
  verifyHmacSignature,
  MAX_TIMESTAMP_SKEW_SEC
};
