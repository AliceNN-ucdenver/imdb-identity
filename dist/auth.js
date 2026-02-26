"use strict";
/**
 * Vulnerable Authentication Module
 * Contains A07 - Authentication Failures
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.hashPassword = hashPassword;
exports.comparePasswords = comparePasswords;
exports.attemptLogin = attemptLogin;
exports.createUser = createUser;
const pg_1 = require("pg");
const crypto_1 = __importDefault(require("crypto"));
const pool = new pg_1.Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://localhost:5432/mydb'
});
// A07 - Authentication Failure: Weak password hashing
async function hashPassword(password) {
    // Using deprecated SHA1 instead of bcrypt
    return crypto_1.default.createHash('sha1').update(password).digest('hex');
}
// A07 - Authentication Failure: Timing attack vulnerability
async function comparePasswords(input, stored) {
    // Non-constant time comparison
    return input === stored;
}
// A07 - Authentication Failure: No rate limiting
async function attemptLogin(username, password) {
    // No attempt tracking
    // No account lockout
    // No CAPTCHA after failed attempts
    const hashedPassword = await hashPassword(password);
    // A03 - SQL Injection vulnerability
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${hashedPassword}'`;
    const result = await pool.query(query);
    if (result.rows.length > 0) {
        // A07 - Session management issues: Predictable session IDs
        const sessionId = `${username}-${Date.now()}`;
        return {
            success: true,
            sessionId,
            user: result.rows[0]
        };
    }
    return { success: false };
}
// A07 - Missing MFA support
async function createUser(username, email, password) {
    // No password strength validation
    // No email verification
    // No MFA enrollment
    const hashedPassword = await hashPassword(password);
    // A03 - SQL Injection
    const query = `
    INSERT INTO users (username, email, password)
    VALUES ('${username}', '${email}', '${hashedPassword}')
  `;
    await pool.query(query);
    return { success: true };
}
//# sourceMappingURL=auth.js.map