const jwt = require('jsonwebtoken');
require('dotenv').config();  // Ensure this is at the top of your entry file

exports.protect = (req, res, next) => {
  // Extract token from Authorization header
  const token = req.headers.authorization?.split(' ')[1];

  // If no token is provided, respond with an error
  if (!token) {
    return res.status(401).json({ success: false, message: 'Unauthorized - No token provided' });
  }

  console.log('Incoming Token:', token); // Log the token to ensure it's being sent correctly

  try {
    // Verify the token using the secret from .env
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    console.log('Decoded Token:', decoded); // Log the decoded token for debugging

    req.user = decoded; // Attach the decoded information to the request object
    next(); // Pass the control to the next middleware or route handler
  } catch (error) {
    // Log the error for debugging purposes
    console.error('JWT Verification Error:', error);

    // Handle different types of JWT verification errors
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, message: 'Token expired' });
    } else if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ success: false, message: 'Invalid token' });
    }

    // General error response
    return res.status(401).json({ success: false, message: 'Unauthorized - Token verification failed' });
  }
};