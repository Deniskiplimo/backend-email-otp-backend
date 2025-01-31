const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const validator = require('validator');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// User Schema Definition
const userSchema = new mongoose.Schema(
  {
    loginId: {
      type: String,
      required: false, // Made loginId optional
    },
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    name: {
      type: String,
      required: false, // Made name optional
      trim: true,
    },
    email: {
      type: String,
      unique: true,
      sparse: true,
      validate: {
        validator: validator.isEmail,
        message: 'Invalid email address',
      },
      required: function () {
        return !this.phoneNumber; // Require either email or phone number
      },
    },
    phoneNumber: {
      type: String,
      unique: true,
      sparse: true,
      validate: {
        validator: function (value) {
          return /^\+\d{1,3}\d{7,15}$/.test(value);
        },
        message: 'Invalid phone number format. Must include country code (e.g., +254742748416)',
      },
      required: function () {
        return !this.email; // Require either email or phone number
      },
    },
    ssn: {
      type: String,
      required: false, // Made SSN optional
    },
    password: {
      type: String,
      required: [true, 'Password is required.'],
      minlength: [6, 'Password must be at least 6 characters long'],
    },
    role: {
      type: String,
      enum: ['user', 'admin'],
      default: 'user',
    },
    ownIdData: {
      type: Object,
      required: false,
    },
    securityQuestions: [
      {
        questionId: { type: String },
        answer: { type: String },
      },
    ],
    resetPasswordToken: {
      type: String,
      default: null,
    },
    resetPasswordExpires: {
      type: Date,
      default: null,
    },
    verificationPin: {
      type: String,
      default: null,
    },
    pinExpiration: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true } // Automatically manages createdAt and updatedAt
);

// Pre-save hook to hash the password before saving the user
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to check if the provided password matches the stored hashed password
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Static method to find a user by email, phone number, or username
userSchema.statics.findByEmailOrPhoneNumberOrUsername = async function (email, phoneNumber, username) {
  return await this.findOne({
    $or: [{ email }, { phoneNumber }, { username }],
  });
};

// Instance method to generate a password reset token
userSchema.methods.generatePasswordReset = function () {
  const token = crypto.randomBytes(20).toString('hex');
  this.resetPasswordToken = token;
  this.resetPasswordExpires = Date.now() + 3600000; // Token expires in 1 hour
  return token;
};

// Instance method to validate the password reset token
userSchema.methods.validatePasswordResetToken = function (token) {
  return this.resetPasswordToken === token && this.resetPasswordExpires > Date.now();
};

// Instance method to generate a 2FA verification PIN and set its expiration
userSchema.methods.generateVerificationPin = function () {
  const pin = Math.floor(100000 + Math.random() * 900000).toString(); // Generate a 6-digit PIN
  this.verificationPin = pin;
  this.pinExpiration = Date.now() + 10 * 60 * 1000; // PIN valid for 10 minutes
  return pin;
};

// Instance method to validate the 2FA verification PIN
userSchema.methods.validateVerificationPin = function (pin) {
  return this.verificationPin === pin && this.pinExpiration > Date.now();
};

// Method to hash and store PIN securely before saving
userSchema.pre('save', async function(next) {
  if (this.isModified('verificationPin')) {
    this.verificationPin = await bcrypt.hash(this.verificationPin, 10); // Hash PIN with bcrypt
  }
  next();
});

// JWT Token generation method
userSchema.methods.generateAuthToken = function () {
  return jwt.sign({ _id: this._id, role: this.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

const User = mongoose.models.User || mongoose.model('User', userSchema);

module.exports = User;