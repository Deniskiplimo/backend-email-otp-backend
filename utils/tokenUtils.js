// utils/tokenUtils.js
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

/**
 * Generate a JWT access token
 * @param {Object} payload - Data to encode in the token
 * @param {string} [expiresIn='1h'] - Token expiration time
 * @returns {string} - The generated JWT token
 */
function generateAccessToken(payload, expiresIn = '1h') {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

/**
 * Generate a JWT refresh token
 * @param {Object} payload - Data to encode in the token
 * @param {string} [expiresIn='7d'] - Token expiration time
 * @returns {string} - The generated JWT token
 */
function generateRefreshToken(payload, expiresIn = '7d') {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

module.exports = {
  generateAccessToken,
  generateRefreshToken
};