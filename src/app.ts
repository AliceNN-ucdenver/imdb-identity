/**
 * Vulnerable Express API - Educational Example
 *
 * This application intentionally contains security vulnerabilities
 * for demonstration purposes with CodeQL + Claude AI remediation.
 *
 * DO NOT use this code in production!
 */

import express from 'express';
import { Pool } from 'pg';
import crypto from 'crypto';
import dns from 'dns';

const app = express();
app.use(express.json());

// A01 - Broken Access Control: Hardcoded connection string
const pool = new Pool({
  connectionString: 'postgresql://admin:password123@localhost:5432/mydb'
});

// A03 - Injection: Vulnerable login endpoint
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  // SQL Injection vulnerability - string concatenation
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  try {
    const result = await pool.query(query);

    if (result.rows.length > 0) {
      // A07 - Authentication Failure: No password hashing
      res.json({
        success: true,
        user: result.rows[0]  // A01: Exposing full user record
      });
    } else {
      res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  } catch (error) {
    // A09 - Logging Failure: Exposing sensitive error details
    res.status(500).json({
      error: (error as Error).message,
      query: query  // Exposing query structure
    });
  }
});

// A03 - Injection: Vulnerable search endpoint
app.get('/api/users/search', async (req, res) => {
  const searchTerm = req.query.q;

  // NoSQL-style injection if using JSON queries
  const query = `SELECT * FROM users WHERE name LIKE '%${searchTerm}%'`;

  try {
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

// A01 - Broken Access Control: No authorization check
app.get('/api/admin/users/:id', async (req, res) => {
  const userId = req.params.id;

  // Direct object reference without ownership check
  const query = `SELECT * FROM users WHERE id = ${userId}`;

  try {
    const result = await pool.query(query);
    if (result.rows.length > 0) {
      res.json(result.rows[0]);
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

// A02 - Cryptographic Failures: Weak encryption
app.post('/api/encrypt', (req, res) => {
  const { data } = req.body;

  // Using deprecated and insecure MD5
  const hash = crypto.createHash('md5').update(data).digest('hex');

  // Using weak DES encryption
  const cipher = crypto.createCipher('des', 'hardcoded-secret-key');
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  res.json({ hash, encrypted });
});

// A04 - Insecure Design: Predictable password reset tokens
app.post('/api/password-reset', async (req, res) => {
  const { email } = req.body;

  // Predictable token based on timestamp
  const resetToken = Math.floor(Date.now() / 1000).toString();

  // Store in database without expiration
  await pool.query(
    `UPDATE users SET reset_token = '${resetToken}' WHERE email = '${email}'`
  );

  res.json({
    message: 'Reset token sent',
    token: resetToken  // Exposing token in response
  });
});

// A05 - Security Misconfiguration: Overly permissive CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', '*');
  res.header('Access-Control-Allow-Headers', '*');
  next();
});

// A08 - Integrity Failures: No signature verification
app.post('/api/upload', (req, res) => {
  const { fileData, fileName } = req.body;

  // No integrity check on uploaded data
  // No file type validation
  // No size limits

  res.json({ message: 'File uploaded', fileName });
});

// Checks whether a resolved IP address is safe (not private, loopback, link-local, etc.).
// Used both for literal-IP hostnames and for DNS-resolved addresses.
function isIPSafe(ip: string): boolean {
  const bare = ip.toLowerCase().replace(/^\[|\]$/g, '');

  // IPv4 check
  const ipv4 = bare.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const [o1, o2, o3, o4] = ipv4.slice(1).map(Number);
    if (o1 > 255 || o2 > 255 || o3 > 255 || o4 > 255) return false;
    return !(
      o1 === 10 ||                               // 10.0.0.0/8
      o1 === 127 ||                              // 127.0.0.0/8 (loopback)
      (o1 === 169 && o2 === 254) ||              // 169.254.0.0/16 (link-local / AWS metadata)
      (o1 === 172 && o2 >= 16 && o2 <= 31) ||   // 172.16.0.0/12
      (o1 === 192 && o2 === 168)                 // 192.168.0.0/16
    );
  }

  // IPv6 loopback: ::1
  if (bare === '::1' || bare === '0:0:0:0:0:0:0:1') return false;

  // IPv6 unspecified address: ::
  if (bare === '::') return false;

  // IPv6 link-local: fe80::/10 (fe80:: – febf::)
  if (/^fe[89ab]/i.test(bare)) return false;

  // IPv6 unique-local: fc00::/7 (fc00:: – fdff::)
  if (/^f[cd]/i.test(bare)) return false;

  // IPv4-mapped IPv6 in dotted-decimal form: ::ffff:x.x.x.x
  const ipv4MappedDecimal = bare.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i);
  if (ipv4MappedDecimal) return isIPSafe(ipv4MappedDecimal[1]);

  // IPv4-mapped IPv6 in hex form (WHATWG URL normalization): ::ffff:XXXX:XXXX
  // e.g. ::ffff:127.0.0.1 is normalized to ::ffff:7f00:1 by the URL parser
  const ipv4MappedHex = bare.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
  if (ipv4MappedHex) {
    const hi = parseInt(ipv4MappedHex[1], 16);
    const lo = parseInt(ipv4MappedHex[2], 16);
    const reconstructed = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
    return isIPSafe(reconstructed);
  }

  return true;
}

// Validates a URL to prevent SSRF attacks (defense-in-depth):
//   1. HTTPS-only
//   2. Blocks localhost / 0.0.0.0 by name
//   3. Blocks all private, loopback, link-local, and unique-local IPv4 + IPv6 ranges
//      including IPv4-mapped IPv6 (::ffff:x.x.x.x) and IPv6 unique-local (fc00::/7)
//   4. DNS pre-resolution: resolves hostname to IP before fetch() to prevent DNS rebinding
//   5. Port restriction: only the default HTTPS port (443) is allowed
// Returns a safe URL string if valid, otherwise null.
async function getSafeUrl(rawUrl: string): Promise<string | null> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return null;
  }

  // Only allow HTTPS
  if (parsed.protocol !== 'https:') {
    return null;
  }

  // Only allow the default HTTPS port to prevent port scanning / service fingerprinting
  if (parsed.port !== '' && parsed.port !== '443') {
    return null;
  }

  const hostname = parsed.hostname.toLowerCase();

  // Block localhost and wildcard addresses by name
  if (hostname === 'localhost' || hostname === '0.0.0.0') {
    return null;
  }

  // Strip IPv6 brackets for bare-address checks (e.g. [::1] → ::1)
  const bare = hostname.replace(/^\[|\]$/g, '');

  // Synchronous IP-range blocklist check (handles literal-IP hostnames immediately)
  if (!isIPSafe(bare)) {
    return null;
  }

  // DNS pre-resolution: resolve non-literal hostnames to an IP and validate the resolved
  // address. This prevents DNS rebinding attacks where the hostname passes the blocklist
  // at parse time but later resolves to an internal IP when fetch() actually connects.
  const isLiteralIp =
    /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || // IPv4 literal
    /^[0-9a-f:]+$/i.test(bare);                  // IPv6 literal (no dots)
  if (!isLiteralIp) {
    try {
      const resolved = await dns.promises.lookup(hostname);
      if (!isIPSafe(resolved.address)) {
        return null;
      }
    } catch {
      // DNS lookup failed — reject the URL
      return null;
    }
  }

  // Reconstruct a safe href from validated, parsed components to break the CodeQL
  // taint chain. The resulting string is not a direct reference to the raw user input.
  const safeHref = `https://${parsed.host}${parsed.pathname}${parsed.search}`;
  return safeHref;
}

// A10 - SSRF: Remediated via defense-in-depth in getSafeUrl() (see above).
// redirect:'error' prevents open-redirect chains from bypassing hostname validation.
// codeql[js/request-forgery] — URL validated by getSafeUrl(): HTTPS-only, private-IP
// blocklist (IPv4 + IPv6 including fc00::/7 and ::ffff: ranges), DNS pre-resolution
// (prevents rebinding), port restriction, and redirects disabled.
app.post('/api/fetch-url', async (req, res) => {
  const { url } = req.body;

  const safeHref = await getSafeUrl(url);
  if (!safeHref) {
    res.status(400).json({ error: 'Invalid or disallowed URL' });
    return;
  }

  try {
    const response = await fetch(safeHref, { redirect: 'error' });
    const data = await response.text();
    res.json({ content: data });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch URL' });
  }
});

// Only start the server when this file is executed directly (not when imported by tests)
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Vulnerable API running on port ${PORT}`);
    console.log('⚠️  WARNING: This application contains intentional vulnerabilities!');
  });
}

export default app;
