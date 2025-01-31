const mongoose = require('mongoose');

const otpSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
  },
  otp: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 300, // 5 minutes expiration
  },
});

// Password reset token schema (if you want to use a separate model)
const resetTokenSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
  },
  resetToken: {
    type: String,
    required: true,
  },
  resetTokenExpires: {
    type: Date,
    required: true,
  },
});

const Otps = mongoose.model('Otps', otpSchema);
const ResetTokens = mongoose.model('ResetTokens', resetTokenSchema);

module.exports = { Otps, ResetTokens };