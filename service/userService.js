const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const User = require('../models/StaffModel');
const logger = require('winston'); // Add your logging tool (e.g., winston) here

// Helper function to validate password strength
const validatePassword = (password) => {
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return passwordRegex.test(password);
};

// Helper function to validate user input data
const validateUserData = (userData) => {
  const { email, password, username, phoneNumber, pfNumber } = userData;
  
  if (!email || !password || !username || !phoneNumber || !pfNumber) {
    throw new AppError('All fields are required.', 400);
  }
};

// Custom Error Handler Class
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode || 400; // Default to bad request
    this.isOperational = true; // Identifies operational errors (user-caused)
    Error.captureStackTrace(this, this.constructor);
  }
}

// Service to find a user by various parameters
const findUser = async (email, phoneNumber, username, userId, pfNumber) => {
  try {
    const query = {};

    if (email) query.email = email;
    if (phoneNumber) query.phoneNumber = phoneNumber;
    if (username) query.username = username;
    if (userId) query._id = userId; // Query by ObjectId
    if (pfNumber) query.pfNumber = pfNumber; // Query by PF number

    const user = await User.findOne(query);
    if (!user) throw new AppError('User not found', 404);

    return user;
  } catch (error) {
    throw new AppError(error.message, 500);
  }
};

// Service to create a new user
const createUser = async (userData) => {
  const { email, password, username, phoneNumber, pfNumber } = userData;

  // Validate input data
  validateUserData(userData);

  // Validate password
  if (!validatePassword(password)) {
    throw new AppError(
      'Password must be at least 8 characters long and contain one uppercase letter, one number, and one special character.',
      400
    );
  }

  const existingUser = await User.findOne({
    $or: [{ email }, { phoneNumber }, { username }, { pfNumber }],
  });

  if (existingUser) {
    throw new AppError('User with this email, phone number, username, or PF number already exists.', 409);
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = new User({ ...userData, password: hashedPassword });

  try {
    await user.save();
    logger.info('User created:', user);
    return user;
  } catch (error) {
    throw new AppError('Error creating user: ' + error.message, 500);
  }
};

// Service to update user details
const updateUser = async (userId, updateData) => {
  try {
    const user = await User.findById(userId);
    if (!user) throw new AppError('User not found', 404);

    if (updateData.password && !validatePassword(updateData.password)) {
      throw new AppError('Password does not meet the required strength.', 400);
    }

    if (updateData.password) {
      updateData.password = await bcrypt.hash(updateData.password, 10);
    }

    Object.assign(user, updateData);
    await user.save();

    logger.info('User updated:', user);
    return user;
  } catch (error) {
    throw new AppError(error.message, 500);
  }
};

// Service to deactivate a user (soft delete)
const deactivateUser = async (userId) => {
  try {
    const user = await User.findById(userId);
    if (!user) throw new AppError('User not found', 404);

    user.isActive = false; // Mark user as inactive (soft delete)
    user.deletedAt = Date.now(); // Add soft delete timestamp
    await user.save();
    
    logger.info('User deactivated:', user);
    return user;
  } catch (error) {
    throw new AppError('Error deactivating user: ' + error.message, 500);
  }
};

// Service to initiate password reset
const resetPassword = async (email, phoneNumber) => {
  try {
    const user = await User.findOne({ $or: [{ email }, { phoneNumber }] });
    if (!user) {
      throw new AppError('No account found with the provided email or phone number', 404);
    }

    // Generate a reset token
    const resetToken = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // Expires in 1 hour

    await user.save();

    // Send reset token via email (implementation needed)
    sendPasswordResetEmail(user.email, resetToken);

    logger.info('Password reset initiated for:', user);
    return resetToken;
  } catch (error) {
    throw new AppError('Error initiating password reset: ' + error.message, 500);
  }
};

// Service to send password reset email (mock function)
const sendPasswordResetEmail = (email, resetToken) => {
  // Implement your email sending logic here
  console.log(`Password reset link: http://yourapp.com/reset-password?token=${resetToken}`);
};

// Service to update password using reset token
const updatePassword = async (resetToken, newPassword) => {
  if (!validatePassword(newPassword)) {
    throw new AppError('Password must be strong and meet the requirements.', 400);
  }

  try {
    const user = await User.findOne({
      resetPasswordToken: resetToken,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      throw new AppError('Invalid or expired password reset token', 400);
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    await user.save();

    logger.info('Password updated for:', user);
    return user;
  } catch (error) {
    throw new AppError('Error updating password: ' + error.message, 500);
  }
};

// Service to get staff with pagination
const getStaffWithPagination = async (page, limit, sort = {}) => {
  try {
    const skip = (page - 1) * limit;
    const staff = await User.find().skip(skip).limit(limit).sort(sort).lean(); // Apply sorting and lean for better performance
    return staff;
  } catch (error) {
    throw new AppError('Error fetching staff list: ' + error.message, 500);
  }
};

// Service to get the total number of staff
const getTotalStaffCount = async () => {
  try {
    return await User.countDocuments();
  } catch (error) {
    throw new AppError('Error counting staff: ' + error.message, 500);
  }
};

module.exports = {
  findUser,
  createUser,
  updateUser,
  deactivateUser,
  resetPassword,
  updatePassword,
  getStaffWithPagination,
  getTotalStaffCount,
};