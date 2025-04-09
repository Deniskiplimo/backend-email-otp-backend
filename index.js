require('dotenv').config();
const { generateCode, summarizeText, translateText } = require('./generalLlama');
const moment = require("moment");
const swaggerJsdoc = require('swagger-jsdoc');
const path = require('path');
const { llamacpp, streamText } = require("modelfusion");
const ip = '8.8.8.8'; 
const { buildSchema } = require("graphql");
const { graphqlHTTP } = require("express-graphql");
const MODELS = require("./models/llama");
const os = require('os'); 
require('web-streams-polyfill'); 
const { execSync } = require("child_process"); 
const { Transform } = require('stream');  
const { body, validationResult ,query} = require("express-validator");
const PORT = process.env.PORT || 3000;
const { parentPort, workerData, isMainThread } = require("worker_threads");
const cors = require("cors");
  
const morgan = require("morgan");
const authenticateRefreshToken = require('./middleware/authenticateRefreshToken');
const express = require('express');   
const mongoose = require('mongoose'); 
const codeLlamaRoutes = require("./routes/codeLlamaRoutes");
const generalLlamaRoutes = require("./routes/generalLlamaRoutes");
const RefreshToken = require('./models/refreshTokenModel');
const { generateAccessToken, generateRefreshToken } = require('./utils/tokenUtils');
const User = require('./models/userModel');
const helmet = require("helmet"); // Security middleware
 
const swaggerUi = require('swagger-ui-express');
const rateLimit = require('express-rate-limit');
const swaggerDocument = require('./swagger.json');
const bodyParser = require('body-parser');
const geoip = require('geoip-lite');
const nodemailer = require('nodemailer');
const geo = geoip.lookup(ip);  // Example usage of geoip to track location of the request
console.log(geo);
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const sendEmail = require('./utils/sendEmail');
const { spawn,exec } = require('child_process');
const axios = require('axios');
const fs = require('fs'); 
const app = express();
const port = process.env.APP_PORT || 3000; // Use APP_PORT for the application server
const aiRoutes = require('./routes/aiRoutes');

const otpRoutes = require('./routes/otpRoutes');
app.use(bodyParser.json());
const winston = require('winston');
require('winston-daily-rotate-file'); // Make sure to require this
app.use(express.json({ limit: "1mb" }));
app.use(cors());
app.use(helmet());
app.use(morgan("combined"));
const transport = new winston.transports.DailyRotateFile({
  filename: 'logs/%DATE%-results.log', // Log file name pattern
  datePattern: 'YYYY-MM-DD',           // Date format for the filename
  zippedArchive: true,                 // Whether to compress old logs
  maxSize: '20m',                      // Max file size before rotation
  maxFiles: '14d'                      // Keep logs for 14 days
});
 
const logger = winston.createLogger({
  level: 'info',
  transports: [
    new winston.transports.Console(),  // Console logging
    transport                          // Log rotation
  ]
});

// Example log
logger.info('This is an info log message');



const STATUS_CODES = {
  OK: 200,
  CREATED: 201,
  ACCEPTED: 202,
  NO_CONTENT: 204,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  INTERNAL_SERVER_ERROR: 500,
  NOT_IMPLEMENTED: 501,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503,
  GATEWAY_TIMEOUT: 504,
};

const ERROR_MESSAGES = {
  MISSING_CREDENTIALS: 'Missing username or password.',
  INVALID_CREDENTIALS: 'Invalid username or password.',
  INTERNAL_ERROR: 'An unexpected error occurred. Please try again later.',
  // Add more error messages as needed
};
 // Example of a route to refresh token
app.post('/refresh-token', authenticateRefreshToken, (req, res) => {
  // Here, you can implement logic to generate a new access token
  const { userId } = req.user;
  const accessToken = jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ accessToken });
});
app.post('/api/refresh-token', async (req, res) => {
  const { refreshToken } = req.body; 
  
  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required' });
  }

  try {
    const existingToken = await RefreshToken.findOne({ token: refreshToken });

    if (!existingToken) {
      return res.status(400).json({ error: 'Invalid or expired refresh token' });
    }

    const { userId } = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

    const newAccessToken = jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '15m' });

    res.status(200).json({ accessToken: newAccessToken });
  } catch (error) {
    console.error('Error refreshing token:', error);
    res.status(500).json({ error: 'Error refreshing token' });
  }
}); 

      // General AI routes

app.use('/api', otpRoutes);
app.use("/api", codeLlamaRoutes);  // CodeLlama endpoints
app.use("/api", generalLlamaRoutes);  // GeneralLlama endpoints
// Connect to MongoDB  
  
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://deniskiplimo593:Denis341170495@cluster0.xc7g7f1.mongodb.net/?retryWrites=true&w=majority&directConnection=true";



// Middleware for security best practices
app.use(helmet());

// Rate limiting to prevent abuse
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: "Too many requests, please try again later."
});
app.use(limiter);

/**
 * @route GET /
 * @desc Default route that provides a welcome message
 * @access Public
 * @bestPractices Keep the response lightweight for quick health checks
 * @security Uses Helmet middleware for security headers
 * @security Implements rate limiting to prevent abuse
 */
app.get("/", (req, res) => {
    res.status(200).json({ message: "Welcome to the Llama & OTP API", status: "healthy" });
});


mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));
// Create transporter object using SMTP transport
const transporter = nodemailer.createTransport({
  host: process.env.HOST,
  port: process.env.PORT,
  secure: process.env.PORT == 465, // true for port 465 (SSL), false for other ports (TLS)
  auth: { 
    user: process.env.USERNAME,
    pass: process.env.PASS,
  },
});

app.get('/', (req, res) => {
  const query = req.query;  // This will give you the query parameters from the URL
  console.log(query);  // Logs the query parameters
  res.send('Query parameters received');
});
app.get('/', (req, res) => {
  const ip = req.ip;  // Get the client's IP address
  const geo = geoip.lookup(ip);  // Use geoip to look up the location
  console.log(geo);  // Logs geo information
  res.send('Location lookup complete');
});

// Route: Fetch geolocation data by IP
app.get(
  '/api/get-location',
  query('ip').optional().isIP().withMessage('Invalid IP address'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    const ip = req.query.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    console.log("IP to lookup:", ip); // Debugging: Output the IP being used for lookup.

    try {
      const userToken = process.env.IPINFO_API_TOKEN; // Get your IPInfo API token from environment variables

      if (!userToken) {
        return res.status(404).json({ success: false, message: 'IPInfo token not found.' });
      }

      // Fetch geolocation data using IPInfo API
      const response = await fetch(`https://ipinfo.io/${ip}/json?token=${userToken}`);
      const data = await response.json();

      // Check if the IPInfo response has valid location data
      if (data.loc) {
        const [latitude, longitude] = data.loc.split(',');

        // Return enhanced location details
        return res.json({
          success: true,
          ip,
          hostname: data.hostname,
          location: {
            city: data.city,
            region: data.region,
            country: data.country,
            latitude: parseFloat(latitude),
            longitude: parseFloat(longitude),
            postal: data.postal || 'Not Available',
            timezone: data.timezone || 'Not Available',
            continent: data.continent || 'Not Available',
            country_code: data.country_code || 'Not Available',
            country_flag: `https://ipapi.co/static/flags/${data.country.toLowerCase()}.png`,
          },
          org: data.org || 'Not Available',
          is_anycast: data.is_anycast || false,
          is_mobile: data.is_mobile || false,
          is_anonymous: data.is_anonymous || false,
          is_satellite: data.is_satellite || false,
          asn: data.asn || 'Not Available',
          company: data.company || 'Not Available',
          privacy: {
            vpn: data.privacy?.vpn || false,
            proxy: data.privacy?.proxy || false,
            tor: data.privacy?.tor || false,
            relay: data.privacy?.relay || false,
            hosting: data.privacy?.hosting || false,
          },
          abuse: data.abuse || 'Not Available',
        });
      } else {
        return res.status(404).json({
          success: false,
          message: `Location data not found for IP: ${ip}`,
        });
      }
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Internal server error. Unable to fetch location data.',
      });
    }
  }
);
// Function to convert degrees to radians
function toRadians(degrees) {
  return degrees * (Math.PI / 180);
}

// Function to calculate the bearing between two points
function calculateBearing(lat1, lon1, lat2, lon2) {
  const lat1Rad = toRadians(lat1);
  const lat2Rad = toRadians(lat2);
  const deltaLon = toRadians(lon2 - lon1);

  const y = Math.sin(deltaLon) * Math.cos(lat2Rad);
  const x = Math.cos(lat1Rad) * Math.sin(lat2Rad) - Math.sin(lat1Rad) * Math.cos(lat2Rad) * Math.cos(deltaLon);

  let bearing = Math.atan2(y, x);
  bearing = (bearing * 180) / Math.PI; // Convert from radians to degrees
  bearing = (bearing + 360) % 360; // Normalize to 0-360 degrees

  return bearing;
}

// Route: Calculate distance between two locations
app.get(
'/api/calculate-distance',
[
    query('lat1').isFloat({ min: -90, max: 90 }).withMessage('Invalid latitude 1'),
    query('lon1').isFloat({ min: -180, max: 180 }).withMessage('Invalid longitude 1'),
    query('lat2').isFloat({ min: -90, max: 90 }).withMessage('Invalid latitude 2'),
    query('lon2').isFloat({ min: -180, max: 180 }).withMessage('Invalid longitude 2'),
],
(req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { lat1, lon1, lat2, lon2 } = req.query;

    try {
        // Parse the coordinates
        const point1 = { latitude: parseFloat(lat1), longitude: parseFloat(lon1) };
        const point2 = { latitude: parseFloat(lat2), longitude: parseFloat(lon2) };

        // Calculate the distance using the Haversine formula or any other method you prefer
        const distanceInMeters = getDistance(point1, point2);

        // Convert meters to other units
        const distanceInKilometers = distanceInMeters / 1000;
        const distanceInMiles = distanceInMeters / 1609.34;
        const distanceInNauticalMiles = distanceInMeters / 1852;

        // Calculate the midpoint using getCenter
        const midpoint = getCenter([point1, point2]);

        // Calculate the bearing between the two points (initial compass bearing)
        const bearing = calculateBearing(parseFloat(lat1), parseFloat(lon1), parseFloat(lat2), parseFloat(lon2));

        console.log(`Distance calculated: ${distanceInMeters} meters`); // Info log

        // Response JSON with detailed information
        res.json({
            success: true,
            distance: {
                meters: distanceInMeters,
                kilometers: distanceInKilometers.toFixed(2),
                miles: distanceInMiles.toFixed(2),
                nautical_miles: distanceInNauticalMiles.toFixed(2)
            },
            midpoint: {
                latitude: midpoint.latitude,
                longitude: midpoint.longitude
            },
            bearing: bearing.toFixed(2), // Return bearing in degrees
            details: {
                origin: point1,
                destination: point2,
                message: 'Distance calculation successful using Haversine formula',
            }
        });
    } catch (error) {
        console.error(`Error calculating distance: ${error.message}`); // Error log
        res.status(500).json({ success: false, message: 'Internal server error.' });
    }
}
);

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  console.log('Authorization Header:', authHeader); // Log the authorization header

  if (!authHeader) {
    console.log('No authorization header found');
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];
  console.log('Extracted Token:', token); // Log the extracted token

  if (token == null) {
    console.log('Token is null');
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      console.error('Token verification error:', err); // Log the verification error
      return res.status(403).json({ error: 'Forbidden: Invalid token' });
    }

    req.user = user; // Attach the user object to the request
    next();
  });
}

module.exports = authenticateToken;

app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
 
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({ error: 'Email already in use' });
    }

    const existingUsername = await User.findOne({ username });
    if (existingUsername) {
      return res.status(400).json({ error: 'Username already in use' });
    }

    const user = new User({ username, email, password });
    await user.save();

    // Return the user's ID and token to the client
    const token = user.generateAuthToken();
    const refreshToken = new RefreshToken({
      token,
      userId: user._id
    });

    await refreshToken.save();

    res.status(201).json({ 
      message: 'User registered successfully', 
      userId: user._id,  // Pass the unique user ID
      token 
    });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ error: 'Error registering user' });
  }
});

async function someFunction() {
  try {
      const result = await someAsyncOperation();  
  } catch (error) {
      console.error('An error occurred:', error);
  }
} 
// Login endpoint
app.post('/api/login', async (req, res) => { 
  const { usernameOrEmail, password } = req.body;

  // Validate inputs
  if (!usernameOrEmail || !password) {
    return res.status(STATUS_CODES.BAD_REQUEST).json({ error: ERROR_MESSAGES.MISSING_CREDENTIALS });
  }

  try {
    // Log request body only in development (avoid logging sensitive data in production)
    if (process.env.NODE_ENV === 'development') {
      console.log('Request body:', req.body);
    }

    // Find user by email or username
    const user = await User.findOne({
      $or: [{ email: usernameOrEmail }, { username: usernameOrEmail }],
    });

    // Check if user exists and if the password matches
    if (!user || !(await user.comparePassword(password))) {
      return res.status(STATUS_CODES.BAD_REQUEST).json({ error: ERROR_MESSAGES.INVALID_CREDENTIALS });
    }

    // Generate JWT access token
    const accessToken = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: process.env.ACCESS_TOKEN_EXPIRES || '15m' } // Default to 15 minutes
    );

    // Generate JWT refresh token
    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: process.env.REFRESH_TOKEN_EXPIRES || '7d' } // Default to 7 days
    );

    // Store refresh token in the database
    await RefreshToken.create({ token: refreshToken, userId: user._id });

    // Respond with tokens and userId
    return res.status(STATUS_CODES.OK).json({ accessToken, refreshToken, userId: user._id });

  } catch (error) {
    // Log error for debugging (but avoid exposing sensitive information)
    console.error('Error logging in:', error.message);

    // Respond with a generic error message
    return res.status(STATUS_CODES.INTERNAL_SERVER_ERROR).json({ error: ERROR_MESSAGES.INTERNAL_ERROR });
  }
}); 

app.post('/api/endpoint', (req, res) => {
  console.log('Request received:', req.body);
  res.send({ message: 'Success' });
});


// Correct order: Initialize before use
const changePasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit to 5 requests per windowMs
  message: "Too many password change attempts, please try again later."
});
// Apply rate limiting middleware to the change-password route
app.post('/api/change-password', changePasswordLimiter, async (req, res) => {
  const { userId, currentPassword, newPassword, confirmPassword } = req.body;

  // Validate that newPassword and confirmPassword match
  if (newPassword !== confirmPassword) {
    return res.status(400).json({
      success: false,
      message: 'New password and confirm password do not match.',
    });
  }

  // Additional password validation: Minimum 8 characters, at least one number, one letter, one special character
  const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  if (!passwordRegex.test(newPassword)) {
    return res.status(400).json({
      success: false,
      message: 'New password must be at least 8 characters long, contain at least one letter, one number, and one special character.',
    });
  }

  try {
    // Find the user in the database
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found.',
      });
    }

    // Check if the current password matches the stored password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: 'Current password is incorrect.',
      });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password in the database
    user.password = hashedPassword;
    await user.save();

    // Log success (optional)
    logSuccess(`User ${userId} changed password successfully`);

    // Respond with a success message
    res.status(200).json({
      success: true,
      message: 'Password updated successfully.',
    });
  } catch (error) {
    // Log error (optional)
    logError(`Error updating password for user ${userId}: ${error.message}`);

    // Handle errors
    res.status(500).json({
      success: false,
      message: 'Internal server error.',
      details: error.message,
    });
  }
});app.get('/api/me', async (req, res) => {
  // Get token from the Authorization header
  const token = req.headers['authorization']?.split(' ')[1];

  // Check if token is provided
  if (!token) {
    return res.status(STATUS_CODES.UNAUTHORIZED).json({ error: ERROR_MESSAGES.ACCESS_TOKEN_REQUIRED });
  }

  try {
    // Verify the token using the secret stored in .env
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Find the user by ID, excluding the password field
    const user = await User.findById(decoded.userId).select('-password');

    // Check if user exists
    if (!user) {
      return res.status(STATUS_CODES.NOT_FOUND).json({ error: ERROR_MESSAGES.USER_NOT_FOUND });
    }

    // Log user activity (e.g., to track who accessed the 'me' endpoint and when)
    await logUserActivity(decoded.userId, 'Accessed /api/me endpoint');

    // Fetch additional details like login history, active sessions, or roles
    const userDetails = {
      user,
      loginHistory: await getLoginHistory(decoded.userId), // Example: Fetch login history if applicable
      activeSessions: await getActiveSessions(decoded.userId), // Example: Fetch active sessions if applicable
      roles: user.roles || [], // Fetch user roles, assuming user object contains roles
      lastLogin: user.lastLogin || null, // Assuming there's a `lastLogin` field
      accountStatus: user.accountStatus || 'active', // Check the account status
      metadata: {
        tokenExpiration: decoded.exp, // Include token expiration time for user's awareness
        issuedAt: decoded.iat, // Include when the token was issued
      },
    };

    // Respond with the enhanced user details
    return res.status(STATUS_CODES.OK).json({ userDetails });
  } catch (error) {
    console.error('Error retrieving user:', error.message);

    // Handle token verification errors
    if (error instanceof jwt.JsonWebTokenError) {
      return res.status(STATUS_CODES.FORBIDDEN).json({ error: ERROR_MESSAGES.INVALID_TOKEN });
    } 
    else if (error instanceof jwt.TokenExpiredError) {
      return res.status(STATUS_CODES.FORBIDDEN).json({ error: ERROR_MESSAGES.TOKEN_EXPIRED });
    }

    // For any other errors, respond with a generic message
    return res.status(STATUS_CODES.INTERNAL_SERVER_ERROR).json({ error: ERROR_MESSAGES.INTERNAL_ERROR });
  }
});

// Helper function to log user activity
async function logUserActivity(userId, activity) {
  try {
    const logEntry = new ActivityLog({
      userId,
      activity,
      timestamp: new Date(),
    });
    await logEntry.save();
  } catch (error) {
    console.error('Error logging user activity:', error.message);
  }
}
app.post('/api/logout', authenticateToken, async (req, res) => {
  const { refreshToken } = req.body;

  // Check if refreshToken is provided
  if (!refreshToken) {
    return res.status(STATUS_CODES.BAD_REQUEST).json({ error: 'Refresh token is required' });
  }

  try {
    // Find the refresh token in the database
    const tokenRecord = await RefreshToken.findOne({ token: refreshToken });

    if (!tokenRecord) {
      return res.status(STATUS_CODES.NOT_FOUND).json({ error: 'Refresh token not found' });
    }

    // Delete the refresh token from the database
    await RefreshToken.deleteOne({ token: refreshToken });

    res.status(STATUS_CODES.OK).json({ message: 'User logged out successfully' });

  } catch (error) {
    console.error('Error logging out:', error);
    res.status(STATUS_CODES.INTERNAL_SERVER_ERROR).json({ error: 'Error logging out' });
  }
});
// ✅ Helper function to download files

// Enhanced downloadFile function with retries and progress
async function downloadFile(url, outputPath, retries = 3, delayMs = 2000) {
  try {
    if (fs.existsSync(outputPath)) {
      console.log(`${outputPath} already exists. Skipping download.`);
      return;
    }

    console.log(`Downloading ${outputPath}...`);
    const writer = fs.createWriteStream(outputPath);
    const response = await axios({ url, method: "GET", responseType: "stream" });
    const totalLength = response.headers["content-length"];
    let downloadedLength = 0;

    response.data.on("data", (chunk) => {
      downloadedLength += chunk.length;
      process.stdout.write(`Downloaded ${(downloadedLength / totalLength * 100).toFixed(2)}% (${downloadedLength} of ${totalLength} bytes)\r`);
    });

    response.data.pipe(writer);

    return new Promise((resolve, reject) => {
      writer.on("finish", () => {
        console.log(`\nDownload of ${outputPath} completed.`);
        fs.chmodSync(outputPath, 0o755); // Add execute permissions
        resolve();
      });
      writer.on("error", (err) => reject(new Error(`Error during download: ${err.message}`)));
    });
  } catch (error) {
    if (retries > 0) {
      console.log(`Error occurred during download. Retrying in ${delayMs}ms...`);
      await new Promise(resolve => setTimeout(resolve, delayMs));
      return downloadFile(url, outputPath, retries - 1, delayMs); // Retry download
    } else {
      throw new Error(`Failed to download ${outputPath} after ${3 - retries + 1} attempts: ${error.message}`);
    }
  }
}

// ✅ Enhanced function to set up the model with parallel downloads and error handling
async function setupModel(port, modelName = "tinyLlama") {
  try {
    const model = MODELS[modelName]; // Get the selected model dynamically
    if (!model) throw new Error(`Model '${modelName}' not found in MODELS.`);

    // Download llamafile executable if not exists
    if (!fs.existsSync("llamafile.exe")) {
      console.log("Downloading llamafile.exe...");
      await downloadFile(
        "https://github.com/Mozilla-Ocho/llamafile/releases/download/0.6/llamafile-0.6",
        "llamafile.exe"
      );
    } else {
      console.log("llamafile.exe already exists, skipping download...");
    }

    // Download the selected model file if not exists
    if (!fs.existsSync(model.filename)) {
      console.log(`Downloading model file ${model.filename}...`);
      await downloadFile(model.url, model.filename);
    } else {
      console.log(`${model.filename} already exists, skipping download...`);
    }

    console.log(`Starting AI server on port ${port} using model: ${model.name}...`);
    
    // Start the AI server with the selected model
    const command = `./llamafile.exe -m tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf --nobrowser --port 4000`;
    execSync(command, (error, stdout, stderr) => {
      if (error) return console.error(`Error: ${error.message}`);
      if (stderr) return console.error(`stderr: ${stderr}`);
      console.log(stdout);
    }); 
  } catch (error) {
    console.error("Setup error:", error);
    throw error;
  }
}

// Example usage: setting up model with port 4000
setupModel(4000, "tinyLlama").then(() => {
  console.log("AI server setup complete.");
}).catch((error) => {
  console.error("Error during setup:", error.message);
});

// ✅ Function to wait for AI server readiness
async function waitForServer(url, retries = 5, delayMs = 2000) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      await axios.get(url);
      console.log(`AI server ready at ${url}`);
      return;
    } catch {
      if (attempt < retries) {
        console.log(`Retrying (${attempt}/${retries})...`);
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      } else {
        throw new Error("AI server failed to start");
      }
    }
  }
}
console.log("Available Models:", MODELS);

// Get the optimal number of threads
const nThreadsDefault = Math.max(2, (os.availableParallelism ? os.availableParallelism() : os.cpus().length) - 1);

// Simple Cache to Avoid Redundant Calls
const responseCache = new Map();
const analytics = {
  cacheHits: 0,
  errors: 0,
  totalRequests: 0,
  totalExecutionTime: 0,
  threadUsage: {
      [nThreadsDefault]: 0
  },
  taskUsage: {},
  taskErrors: {},
  avgResponseTime: {},
  responseStats: {} // To track min/max response length per task
};

// Function to Execute Llama Model
async function executeLlama(options = {}) {
  const {
      prompt,
      model = "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
      task = "default",
      socket = null,
      maxTokens = Math.min(512, Math.max(128, Math.ceil(prompt.length * 1.5))), // Dynamic Token Control
      temperature = prompt.length > 100 ? 0.5 : 0.7, // Adaptive Temperature Decay
      topK = 50,
      topP = 0.9, // Added Nucleus Sampling
      repetitionPenalty = 1.2, // Prevents AI from repeating itself
      frequencyPenalty = 0.8, // Penalizes overused words
      nThreads = nThreadsDefault,
      useCache = true, // Enable caching for repeated queries
      stopSequences = ["\n", "END"], // Stops unnecessary continuations
      debug = false, // Enable detailed logs
  } = options;

  // Validate Input
  if (!prompt || typeof prompt !== "string" || prompt.trim() === "") {
      console.error("❌ Invalid prompt received:", prompt);
      analytics.errors++;
      return Promise.reject({
          message: "❌ Invalid prompt",
          details: "Prompt must be a non-empty string.",
      });
  }

  console.log(`📝 Running Llama with prompt: "${prompt}" using ${nThreads} threads`);
  if (debug) console.log(`🔍 [DEBUG] Max Tokens: ${maxTokens}, Temp: ${temperature}`);

  // Track total requests
  analytics.totalRequests++;

  // Track start time
  const startTime = Date.now();

  // Check Cache
  if (useCache && responseCache.has(prompt)) {
      console.log("✅ Returning cached response");
      analytics.cacheHits++;
      const elapsedTime = Date.now() - startTime;
      analytics.totalExecutionTime += elapsedTime;
      return responseCache.get(prompt);
  }

  try {
      // Run the model
      const result = await runLlamaModel({
          prompt,
          model,
          socket,
          maxTokens,
          temperature,
          topK,
          topP, // Added
          repetitionPenalty, // Added
          frequencyPenalty, // Added
          nThreads,
          stopSequences, // Added
      });

      // Track elapsed time for execution
      const elapsedTime = Date.now() - startTime;
      analytics.totalExecutionTime += elapsedTime;

      // Store in Cache
      if (useCache) {
          responseCache.set(prompt, result);
      }

      return result;
  } catch (error) {
      console.error("❌ Error executing Llama:", error.message);
      analytics.errors++;
      return { error: "Llama execution failed", details: error.message };
  }
}

// Function to log analytics (could be extended to send this data to a remote server or store in a database)
function logAnalytics() {
  console.log("📊 Analytics Report:");
  console.log(`Total Requests: ${analytics.totalRequests}`);
  console.log(`Cache Hits: ${analytics.cacheHits}`);
  console.log(`Total Errors: ${analytics.errors}`);
  console.log(`Total Execution Time (ms): ${analytics.totalExecutionTime}`);
  console.log(`Average Execution Time (ms): ${analytics.totalExecutionTime / analytics.totalRequests}`);
  console.log("Thread Usage:", analytics.threadUsage);
  console.log("Task Usage:", analytics.taskUsage);
  console.log("Task Errors:", analytics.taskErrors);
  console.log("Average Response Times:", analytics.avgResponseTime);
  console.log("Response Stats (min/max length per task):", analytics.responseStats);
}

module.exports = { executeLlama, logAnalytics };

// Generic AI Request Handler
const handleAIRequest = async (req, res, task, promptTemplate) => {
  try {
      const startTime = Date.now(); // Start time tracking

      // Generate the prompt using the provided template
      const prompt = promptTemplate(req.body);
      if (!prompt || typeof prompt !== "string" || prompt.trim() === "") {
          return res.status(400).json({ error: "Invalid prompt", details: "Prompt cannot be empty" });
      }

      // Increment request analytics
      analytics.totalRequests++;
      analytics.taskUsage[task] = (analytics.taskUsage[task] || 0) + 1;

      console.log(`🔍 [${task}] Processing request...`);

      // Execute AI request
      const response = await executeLlama({ prompt, task, stream: true });

      // Validate Response
      if (!response || (!response.response && typeof response !== "string")) {
          console.error(`❌ [${task}] AI response is empty`);
          trackError(task, "Empty Response");
          return res.status(500).json({ error: "AI response is empty", details: response });
      }

      const executionTime = Date.now() - startTime;
      const finalResponse = response.response ? response.response.trim() : response.trim();
      const responseLength = finalResponse.length;

      // Update Response Statistics
      updateResponseStats(task, responseLength);

      // Update Response Time Metrics
      if (!analytics.avgResponseTime[task]) {
          analytics.avgResponseTime[task] = executionTime;
      } else {
          analytics.avgResponseTime[task] =
              (analytics.avgResponseTime[task] + executionTime) / 2;
      }

      console.log(
          `✅ [${task}] Success in ${executionTime}ms | Length: ${responseLength} chars`
      );

      // Handle Streaming Response
      if (response.stream) {
          res.setHeader("Content-Type", "text/event-stream");
          res.setHeader("Cache-Control", "no-cache");
          res.setHeader("Connection", "keep-alive");

          for await (const chunk of response.stream) {
              res.write(`data: ${JSON.stringify({ status: "streaming", chunk })}\n\n`);
          }
          res.end();
          return;
      }

      res.json({ status: "success", response: finalResponse });
  } catch (error) {
      console.error(`❌ [${task}] Error:`, error.message);
      trackError(task, error.message);
      handleError(res, error, `${task} failed`);
  }
};

// Function to track errors per task
const trackError = (task, message) => {
  analytics.errors++;
  analytics.taskErrors[task] = (analytics.taskErrors[task] || 0) + 1;
  console.error(`❌ [${task}] Error recorded: ${message}`);
};

// Function to track response length statistics
const updateResponseStats = (task, length) => {
  if (!analytics.responseStats[task]) {
      analytics.responseStats[task] = { min: length, max: length };
  } else {
      analytics.responseStats[task].min = Math.min(analytics.responseStats[task].min, length);
      analytics.responseStats[task].max = Math.max(analytics.responseStats[task].max, length);
  }
};

// Endpoint to Fetch Analytics
const getAnalytics = (req, res) => {
  res.json({
      totalRequests: analytics.totalRequests,
      taskUsage: analytics.taskUsage,
      avgResponseTime: analytics.avgResponseTime,
      errorCount: analytics.errors,
      taskErrors: analytics.taskErrors,
      responseStats: analytics.responseStats, // Includes min/max response lengths
  });
};

module.exports = { handleAIRequest, getAnalytics };
async function runLlamaModel({ prompt, model, socket, maxTokens, temperature, topK, nThreads, port = PORT }) { 
  return new Promise(async (resolve, reject) => {
      console.log("🚀 Executing Llama:", { port, prompt, maxTokens, temperature, topK, nThreads });

      if (!port) {
          return reject({ message: "❌ Port is missing!" });
      }

      // Retry connection if Llama server is unavailable
      for (let attempt = 1; attempt <= 3; attempt++) {
          const isServerReady = await checkServerAvailability(`https://backend-email-otp-backend-wzo6.onrender.com`);  // Using the Render server URL
          if (isServerReady) break;
          if (attempt === 3) return reject({ message: "❌ Llama server is not available after retries" });
          console.log(`🔄 Retry ${attempt}/3: Waiting for Llama server...`);
          await new Promise((res) => setTimeout(res, 2000));
      }

      const llamaSystemPrompt =
          `You are an AI assistant here to help with programming tasks. ` +
          `Your responses will be clear, concise, and code-oriented. ` +
          `Please follow the instructions and generate the requested code.`;

      // Initialize Llama API for Render server
      const api = llamacpp.createApi({ baseUrl: `https://backend-email-otp-backend-wzo6.onrender.com` });  // Update to Render URL

      try {
          const timeout = 7000; // Increased timeout for stability
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), timeout);

          const textStream = await streamText({
              signal: controller.signal,
              model: llamacpp
                  .CompletionTextGenerator({
                      api: api,
                      temperature: temperature,
                      stopSequences: ["\n```"],
                  })
                  .withInstructionPrompt(),
              prompt: {
                  system: llamaSystemPrompt,
                  instruction: prompt,
                  responsePrefix: `Here is the response:\n`,
              },
          });

          let response = "";
          for await (const textPart of textStream) {
              process.stdout.write(textPart);
              response += textPart;
              if (socket) socket.emit("ai_response", { chunk: textPart });
          }

          clearTimeout(timeoutId);
          resolve({
              status: "success",
              message: "Response generated successfully",
              response: response.trim(),
          });
      } catch (error) {
          console.error("❌ Error generating response:", error.message);
          reject({ message: "Llama Execution Failed", details: error.message });
      }
  });
}



// Check if the server is available
async function checkServerAvailability(port) {
    console.log("🔍 Checking server availability on port:", port);

    if (!port) {
        console.error("❌ Port is undefined or invalid");
        return false;
    }

    const serverUrl = `http://localhost:${port}`;
    try {
        await axios.get(serverUrl);
        console.log(`✅ AI server is ready at ${serverUrl}`);
        return true;
    } catch (error) {
        console.error(`❌ Server is unavailable at ${serverUrl}`);
        return false;
    }
}

// Check server health
async function checkServerHealth() {
    try {
        const response = await axios.get(`http://localhost:${PORT}/health`);
        if (response.status === 200) {
            console.log("✅ Server is up and running");
            return true;
        }
        return false;
    } catch (error) {
        console.error("❌ Server health check failed");
        return false;
    } 
}


// Start checking server availability
checkServerAvailability(PORT);

module.exports = { runLlamaModel, checkServerAvailability, checkServerHealth };


// ✅ Middleware for request validation
const validateRequest = (fields) => (req, res, next) => {
  const missingFields = fields.filter((field) => !req.body[field]);
  if (missingFields.length) {
    return res.status(400).json({ error: `Missing fields: ${missingFields.join(", ")}` });
  }
  next();
};
// ✅ Function to handle API responses
async function handleLlamaRequest(req, res, responseFunction) {
  try {
    if (!req.body || typeof req.body !== 'object') {
      return res.status(400).json({ error: 'Invalid request body' });
    }

    const { instruction } = req.body;
    if (!instruction) {
      return res.status(400).json({ error: 'Instruction is required' });
    }

    console.log(`📩 Received instruction: ${instruction}`);
    const response = await responseFunction(instruction);

    res.status(200).json({ response });
  } catch (error) {
    console.error('❌ Error processing request:', error);
    res.status(500).json({ error: 'An error occurred while processing the request', details: error.message });
  }
}

// Middleware for logging request details
app.use((req, res, next) => {
  const startTime = Date.now();

  res.on("finish", () => {
    const duration = Date.now() - startTime;
    console.log(`📡 [${moment().format("YYYY-MM-DD HH:mm:ss")}] ${req.method} ${req.originalUrl} - ${res.statusCode} (${duration}ms)`);
  });

  next();
});

// ✅ Logging middleware for detailed request tracking
const logRequest = (req, res, next) => {
  console.log(`📩 [${moment().format("YYYY-MM-DD HH:mm:ss")}] Incoming request: ${req.method} ${req.originalUrl}`);
  console.log(`📜 Request Body:`, req.body);
  next();
};

// ✅ Enhanced API Routes with logging
app.post("/api/llama", logRequest, async (req, res) => {
  await handleLlamaRequest(req, res, executeLlama);
});

// Endpoint to interact with the Llama model
app.post('/api/llama', async (req, res) => {
  const { prompt, temperature = 0.7, maxTokens = 150, topK = 50, nThreads = 4 } = req.body;

  console.log("Received prompt:", prompt);  // Log the prompt to debug the request

  if (!prompt) {
      return res.status(400).json({ error: "❌ Prompt is required!" });
  }

  try {
      // Ensure Llama server is ready before processing
      const isServerReady = await checkLlamaServer();
      if (!isServerReady) {
          return res.status(500).json({ error: "❌ Llama model server is not available." });
      }

      // Initialize Llama API
      const api = new llamacpp.Api({ baseUrl: 'http://localhost:4000' });  // Adjust if using a different port

      // Set up the Llama model and generate text using the prompt
      const textStream = await streamText({
          model: new llamacpp.CompletionTextGenerator({
              api,
              temperature,
              topK,
              nThreads,
          }).withInstructionPrompt(),
          prompt: {
              system: 'You are an AI assistant here to help with programming tasks.',
              instruction: prompt,
              responsePrefix: 'Here is the response:\n',
          },
      });

      let response = '';
      for await (const textPart of textStream) {
          response += textPart;
      }

      return res.json({ response: response.trim() });

  } catch (error) {
      console.error("❌ Error generating response:", error);
      return res.status(500).json({ error: "Failed to generate response", details: error.message });
  }
});

// ✅ Completion API
app.post("/completion", async (req, res) => {
  try {
    const { instruction, prompt } = req.body;
    const finalPrompt = instruction || prompt;

    if (!finalPrompt) {
      return res.status(400).json({ error: "Instruction is required" });
    }

    console.log(`[INFO] Received instruction: ${finalPrompt}`);

    const response = await executeLlama({ prompt: finalPrompt });

    res.status(200).json({ response });
  } catch (error) {
    console.error("❌ Error handling /completion request:", error);
    res.status(500).json({
      error: "Internal Server Error",
      details: error.message || "Unexpected error occurred.",
    });
  }
});

// ✅ AI Server Start API

// ✅ Start AI Server
app.post("/start", async (req, res) => {
  try {
    console.log("[AI] Starting AI Server...");
    
    await setupModel(AI_PORT);
    await waitForServer(`http://localhost:${AI_PORT}`);

    console.log(`[AI] Server started successfully on port ${AI_PORT}`);
    res.json({ message: "AI Server started successfully", port: AI_PORT });

  } catch (error) {
    console.error("[AI] Failed to start:", error);
    res.status(500).json({ error: "AI Server failed to start", details: error.message });
  }
});

// ✅ AI Execution API
app.post(
  "/api/ai/execute",
  [
    body("prompt").notEmpty().withMessage("Prompt is required"),
    body("maxTokens").optional().isInt({ min: 1 }).withMessage("maxTokens must be a positive integer"),
    body("temperature").optional().isFloat({ min: 0, max: 1 }).withMessage("temperature must be between 0 and 1"),
    body("topK").optional().isInt({ min: 1 }).withMessage("topK must be a positive integer"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: "Invalid request", details: errors.array() });
    }

    try {
      const { prompt, task, maxTokens, temperature, topK } = req.body;
      console.log("[AI] Executing AI with params:", { prompt, task, maxTokens, temperature, topK });

      const response = await executeLlama({ prompt, task, maxTokens, temperature, topK });

      if (!response || Object.keys(response).length === 0) {
        return res.status(500).json({ error: "AI execution returned an empty response" });
      }

      res.json({
        status: "success",
        message: "Response generated successfully",
        response,
      });

    } catch (error) {
      console.error("[AI] Execution failed:", error);
      res.status(500).json({ error: "Execution failed", details: error.message });
    }
  }
);

// ✅ AI Summarization API
app.post(
  "/api/ai/summarize",
  [
    body("text").notEmpty().withMessage("Text is required"),
    body("maxTokens").optional().isInt({ min: 1 }).withMessage("maxTokens must be a positive integer"),
    body("temperature").optional().isFloat({ min: 0, max: 1 }).withMessage("temperature must be between 0 and 1"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: "Invalid request", details: errors.array() });
    }

    try {
      const { text, maxTokens, temperature } = req.body;
      console.log("[AI] Summarizing text...");

      const response = await executeLlama({
        prompt: `Summarize: ${text}`,
        task: "summarization",
        maxTokens,
        temperature,
      });

      res.json({ status: "success", message: "Summarization successful", response });

    } catch (error) {
      console.error("[AI] Summarization failed:", error);
      res.status(500).json({ error: "Summarization failed", details: error.message });
    }
  }
);

// Utility function for error handling
const handleError = (res, message, error) => {
  console.error(`❌ ${message}:`, error);
  res.status(500).json({ error: message, details: error.message || error });
};

// AI Task Handler
const handleAITask = async (req, res, prompt, task, options = {}) => {
  try {
    const response = await executeLlama({ prompt, task, ...options });
    if (!response || !response.response || response.response.trim() === "") {
      return res.status(500).json({ error: "AI model returned an invalid response" });
    }
    res.json({ status: "success", response: response.response.trim() });
  } catch (error) {
    handleError(res, `${task} failed`, error);
  }
};

// AI Routes
app.post("/api/ai/generate-blog", async (req, res) => {
  const { topic, wordCount, tone, temperature = 0.7 } = req.body;
  if (!topic) return res.status(400).json({ error: "Topic is required" });
  await handleAITask(req, res, `Write a ${tone} blog post on: ${topic}`, "text-generation", { maxTokens: wordCount, temperature });
});

app.post("/api/ai/image-caption", async (req, res) => {
  const { imageUrl } = req.body;
  if (!imageUrl) return res.status(400).json({ error: "Image URL is required" });
  await handleAITask(req, res, `Describe the content of this image: ${imageUrl}.`, "image-captioning");
});

app.post("/api/ai/extract-keywords", async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: "Text is required" });
  await handleAITask(req, res, `Extract key topics from: ${text}`, "keyword-extraction");
});

app.post("/api/ai/paraphrase", async (req, res) => {
  const { text, style = "neutral" } = req.body;
  if (!text) return res.status(400).json({ error: "Text is required" });
  await handleAITask(req, res, `Paraphrase the following text in a ${style} tone: "${text}"`, "paraphrasing");
});

app.post("/api/ai/translate", async (req, res) => {
  const { text, sourceLang, targetLang } = req.body;
  if (!text || !sourceLang || !targetLang) return res.status(400).json({ error: "Text, sourceLang, and targetLang are required" });
  await handleAITask(req, res, `Translate '${text}' from ${sourceLang} to ${targetLang}:`, "translation");
});

app.post("/api/ai/generate-code", async (req, res) => {
  const { description, language, maxTokens = 100, temperature = 0.7 } = req.body;
  if (!description || !language) return res.status(400).json({ error: "Description and language are required" });
  await handleAITask(req, res, `Write a ${language} function to ${description}.`, "code-generation", { maxTokens, temperature });
});

app.post("/api/ai/chat", async (req, res) => {
  const { message, context, temperature = 0.7 } = req.body;
  if (!message) return res.status(400).json({ error: "Message is required" });

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");

  try {
    const stream = await streamText(`Chatbot response to: '${message}' in context '${context}'`, { temperature });

    for await (const chunk of stream) {
      res.write(`data: ${JSON.stringify({ chunk })}\n\n`);
    }
    
    res.end();
  } catch (error) {
    console.error("AI error:", error);
    res.status(500).json({ error: "AI service failed" });
  }
});

app.post("/api/ai/generate-sql", async (req, res) => {
  const { description, databaseType, temperature = 0.7 } = req.body;
  if (!description || !databaseType) return res.status(400).json({ error: "Description and databaseType are required" });
  await handleAITask(req, res, `Generate a ${databaseType} SQL query that performs: ${description}`, "sql-generation", { temperature });
});

app.post("/api/ai/sentiment", async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: "Text is required" });
  await handleAITask(req, res, `Classify the sentiment of this text: "${text}"`, "sentiment-analysis", { maxTokens: 50 });
});
// ✅ AI Data Analysis


 



// API to Get Analytics by Time Range
const { stringify } = require("flatted"); // Alternative to handle circular references

app.get("/api/analytics/time", async (req, res) => {
    try {
        const aiResponse = await getAIAnalyticsTime(); // Assuming this is your AI API call

        console.log("Raw AI Response:", aiResponse); // Log AI response before processing

        if (!aiResponse || Object.keys(aiResponse).length === 0) {
            return res.status(500).json({ success: false, message: "AI response is empty" });
        }

        // Ensure the response is serializable
        const safeData = JSON.parse(JSON.stringify(aiResponse, (key, value) =>
            key === "socket" || key === "parser" ? undefined : value
        ));

        res.json({
            success: true,
            message: "Analytics data fetched",
            data: safeData
        });

    } catch (error) {
        console.error("Error fetching analytics:", error);

        // Handle circular JSON error
        if (error.message.includes("circular structure")) {
            return res.status(500).json({
                success: false,
                message: "Server error: Circular reference detected",
                error: stringify(error) // Use 'flatted' to handle circular structures
            });
        }

        res.status(500).json({
            success: false,
            message: "Internal server error",
            error: error.message
        });
    }
});


 

// API to Stream Analytics Data
app.get("/api/analytics/stream", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");

  setInterval(() => {
    handleAIRequest(req, res, "analytics-stream", () => "Stream live analytics data.");
  }, 5000); // Sends update every 5s
});

// GraphQL API for Analytics
const schema = buildSchema(`
  type Query {
    totalRequests: Int
    totalErrors: Int
    avgExecutionTime: Float
  }
`);

const root = {
  totalRequests: () => handleAIRequest({}, {}, "analytics-graphql", () => "Get total requests."),
  totalErrors: () => handleAIRequest({}, {}, "analytics-graphql", () => "Get total errors."),
  avgExecutionTime: () => handleAIRequest({}, {}, "analytics-graphql", () => "Get average execution time."),
};

app.use("/api/analytics/graphql", graphqlHTTP({
  schema,
  rootValue: root,
  graphiql: true,
}));

// API to Get Dashboard Data
app.get("/api/analytics/dashboard", (req, res) => {
  handleAIRequest(req, res, "analytics-dashboard", () => "Get dashboard analytics data.");
});
app.get("/api/ai/analytics", (req, res) => {
  handleAIRequest(req, res, "analytics-ai", (query) => {
    const { task, startTime, endTime, errorsOnly } = query;

    // Ensure analytics object exists
    if (!analytics || !analytics.executionTimes || !analytics.taskStats) {
      console.error("Analytics data is missing");
      return "Error: Analytics data is not available.";
    }

    let filteredRequests = analytics.executionTimes.map((time, index) => ({
      task: Object.keys(analytics.taskStats)[index] || "unknown",
      executionTime: time,
      timestamp: Date.now() - time,
    }));

    if (task) {
      filteredRequests = filteredRequests.filter((entry) => entry.task === task);
    }

    if (startTime || endTime) {
      const start = startTime ? new Date(startTime).getTime() : 0;
      const end = endTime ? new Date(endTime).getTime() : Date.now();
      filteredRequests = filteredRequests.filter((entry) => entry.timestamp >= start && entry.timestamp <= end);
    }

    // Apply errorsOnly filter if requested
    if (errorsOnly === "true") {
      filteredRequests = filteredRequests.filter((entry) => entry.task === "error");
    }

    const executionTimes = filteredRequests.map((entry) => entry.executionTime);
    const totalRequests = executionTimes.length;
    const totalErrors = analytics.errorCount || 0;
    const avgExecutionTime = totalRequests ? executionTimes.reduce((a, b) => a + b, 0) / totalRequests : 0;
    const minExecutionTime = executionTimes.length ? Math.min(...executionTimes) : null;
    const maxExecutionTime = executionTimes.length ? Math.max(...executionTimes) : null;
    const variance = executionTimes.length > 1 ? executionTimes.reduce((sum, val) => sum + Math.pow(val - avgExecutionTime, 2), 0) / executionTimes.length : 0;
    const stdDeviation = Math.sqrt(variance);

    // ✅ Return as a **string** instead of an object
    return JSON.stringify({
      totalRequests,
      totalErrors,
      avgExecutionTime: avgExecutionTime.toFixed(2),
      minExecutionTime,
      maxExecutionTime,
      stdDeviation: stdDeviation.toFixed(2),
      taskStats: analytics.taskStats,
    });
  });
});


// AI Routes
app.post("/api/ai/analyze-data", logRequest, validateRequest(["dataset", "question"]), (req, res) => {
  handleAIRequest(req, res, "data-analysis", (body) => `Analyze this dataset and answer: ${body.question}\n${JSON.stringify(body.dataset)}`);
});

app.post("/api/ai/grammar-check", logRequest, validateRequest(["text"]), (req, res) => {
  handleAIRequest(req, res, "grammar-correction", (body) => `Correct the grammar in: ${body.text}`);
});


app.post("/api/ai/chatbot", logRequest, validateRequest(["message"]), (req, res) => {
  try {
    const message = req.body.message;

    if (!message || typeof message !== "string" || message.trim() === "") {
      return res.status(400).json({ error: "Invalid input: 'message' must be a non-empty string." });
    }

    console.log(`📩 Incoming Chatbot Message: "${message}"`);

    handleAIRequest(req, res, "chatbot", (body) => body.message);
  } catch (error) {
    console.error("❌ Chatbot Request Error:", error);
    res.status(500).json({ error: "Internal Server Error", details: error.message });
  }
});
    
 
// Ensure the videos directory exists
const videosDir = path.join(__dirname, 'generated_videos');
if (!fs.existsSync(videosDir)) {
  fs.mkdirSync(videosDir, { recursive: true });
}

// Define the generated background path
const generatedBackgroundPath = path.join(videosDir, 'generated_background.mp4');

// Function to generate a dynamic background video
function generateBackgroundVideo(callback) {
  const pythonExecutable =
    process.platform === 'win32'
      ? path.join(__dirname, 'venv', 'Scripts', 'python.exe')
      : path.join(__dirname, 'venv', 'bin', 'python');

  const backgroundScript = path.join(__dirname, 'generate_background.py');

  const command = `"${pythonExecutable}" "${backgroundScript}" --output "${generatedBackgroundPath}"`;

  console.log('⏳ Generating background video...');

  try {
    execSync(command, { stdio: 'inherit' });
    // Check if the video file is valid after generation
    if (fs.existsSync(generatedBackgroundPath)) {
      const stats = fs.statSync(generatedBackgroundPath);
      if (stats.size > 0) {
        console.log(`✅ Background video generated at: ${generatedBackgroundPath}`);
        callback(null); // No error, proceed
      } else {
        console.error('❌ Generated background video is empty');
        callback(new Error('Generated background video is empty'));
      }
    } else {
      console.error('❌ Background video not generated');
      callback(new Error('Background video not generated'));
    }
  } catch (error) {
    console.error(`⚠️ Background generation failed: ${error.message}`);
    callback(new Error('Background generation failed'));
  }
}

app.post('/api/ai/text-to-video', async (req, res) => {
  try {
    const { text } = req.body;
    if (!text) {
      return res.status(400).json({ error: "Missing required 'text' field" });
    }

    console.log(`🎥 Generating video for: "${text}"`);

    // Define video output path
    const videoFilename = `${text.replace(/\s+/g, '_')}.mp4`;
    const videoPath = path.join(videosDir, videoFilename);

    // Ensure background is generated before proceeding
    if (!fs.existsSync(generatedBackgroundPath)) {
      console.log('⚡ Background video not found. Generating now...');
      generateBackgroundVideo((error) => {
        if (error) {
          return res.status(500).json({ error: 'Failed to generate background video', details: error.message });
        }
        processVideo(text, videoPath, res);
      });
    } else {
      processVideo(text, videoPath, res);
    }
  } catch (error) {
    console.error('❌ Error processing request:', error);
    res.status(500).json({ error: 'Internal Server Error', details: error.message });
  }
});

// Function to handle video generation after background creation
function processVideo(text, videoPath, res) {
  const pythonExecutable =
    process.platform === 'win32'
      ? path.join(__dirname, 'venv', 'Scripts', 'python.exe')
      : path.join(__dirname, 'venv', 'bin', 'python');

  const pythonScript = path.join(__dirname, 'generate_video.py');

  // Execute Python script to generate the final video
  const command = `"${pythonExecutable}" "${pythonScript}" --text "${text}" --input "${generatedBackgroundPath}" --output "${videoPath}" --format "mp4"`;

  console.log(`🚀 Running video generation command:\n${command}`);

  exec(command, (error, stdout, stderr) => {
    console.log(`📜 Raw stdout: ${stdout.trim()}`);
    console.log(`📜 Raw stderr: ${stderr.trim()}`);

    if (error) {
      console.error(`❌ Video generation error: ${error.message}`);
      return res.status(500).json({ error: 'Video generation failed', details: stderr.trim() });
    }

    if (!fs.existsSync(videoPath)) {
      console.error(`❌ Video file not found: ${videoPath}`);
      return res.status(500).json({ error: 'Video file not found after generation' });
    }

    const videoUrl = `${res.req.protocol}://${res.req.get('host')}/videos/${path.basename(videoPath)}`;
    res.json({ status: 'success', videoUrl });
  });
}

// Serve videos statically
app.use('/videos', express.static(videosDir));


// AI-Powered Sentiment Analysis
app.post("/api/social/sentiment-analysis", logRequest, validateRequest(["text"]), (req, res) => {
  handleAIRequest(req, res, "sentiment-analysis", (body) => `Analyze sentiment: \"${body.text}\".`);
});

// AI-Powered Fake News Detection
app.post("/api/social/fake-news-detection", logRequest, validateRequest(["articleText"]), (req, res) => {
  handleAIRequest(req, res, "fake-news-detection", (body) => `Analyze if this article contains fake news: \"${body.articleText}\".`);
});

// AI-Powered Hashtag Recommendation
app.post("/api/social/recommend-hashtags", async (req, res) => {
  try {
    // Accept content from either query params or body
    const content = req.body.content || req.query.content;
    if (!content) {
      return res.status(400).json({ error: "Content is required" });
    }

    const prompt = `Suggest three relevant hashtags for: "${content}".`;
    
    // Ensure `executeLlama` runs properly
    const response = await executeLlama({ prompt, task: "hashtag-recommendation" });

    if (!response || !response.response) {
      throw new Error("Invalid response from AI model");
    }

    // Parse and sanitize hashtags
    let hashtags = response.response.trim().split(/,\s*/).map(tag => tag.startsWith("#") ? tag : `#${tag}`);

    res.json({ status: "success", hashtags });
  } catch (error) {
    console.error("Hashtag recommendation error:", error);
    res.status(500).json({ error: "Hashtag recommendation failed", details: error.message });
  }
});

// AI-Powered Post Scheduling Suggestion
app.post("/api/social/suggest-post-time", async (req, res) => {
  try {
    const content = req.body.content || req.query.content;
    const platform = req.body.platform || req.query.platform;

    if (!content || !platform) {
      return res.status(400).json({ error: "Content and platform are required" });
    }

    const prompt = `Suggest the best posting time on ${platform} for: "${content}".`;
    const response = await executeLlama({ prompt, task: "post-scheduling" });

    if (!response || !response.response) {
      throw new Error("Invalid response from AI model");
    }

    res.json({ status: "success", bestTime: response.response.trim() });
  } catch (error) {
    console.error("Post scheduling error:", error);
    res.status(500).json({ error: "Post scheduling suggestion failed", details: error.message });
  }
});

// AI-Powered Automated Replies
app.post("/api/social/auto-reply", async (req, res) => {
  try {
    const message = req.body.message || req.query.message;

    if (!message) {
      return res.status(400).json({ error: "Message is required" });
    }

    const prompt = `Generate a reply to: "${message}".`;
    const response = await executeLlama({ prompt, task: "auto-reply" });

    if (!response || !response.response) {
      throw new Error("Invalid response from AI model");
    }

    res.json({ status: "success", reply: response.response.trim() });
  } catch (error) {
    console.error("Auto-reply error:", error);
    res.status(500).json({ error: "Auto-reply generation failed", details: error.message });
  }
});
// AI-Powered Image Captioning
app.post("/api/social/generate-caption", logRequest, (req, res) => {
  handleAIRequest(req, res, "image-captioning", (body) => {
    const imageUrl = body.imageUrl || req.query.imageUrl;
    if (!imageUrl) {
      throw new Error("Image URL is required");
    }
    return `Describe this image: "${imageUrl}".`;
  });
}); 

// AI-Powered Trend Analysis
app.post("/api/social/analyze-trends", logRequest, (req, res) => {
  handleAIRequest(req, res, "trend-analysis", (body) => {
    const topic = body.topic || req.query.topic;
    if (!topic) {
      throw new Error("Topic is required");
    }
    return `Analyze social media trends on: "${topic}".`;
  });
});
 
// 📩 AI-Generated SMS
const sendDebtReminderSMS = async (debtor) => {
  const task = "Debt Collection SMS";
  const prompt = `Generate a polite yet firm debt reminder for ${debtor.name} who owes $${debtor.amountDue}.`;

  const response = await executeLlama({ prompt, task });
  const message = response.response.trim();

  console.log(`📩 Sending SMS to ${debtor.phone}: "${message}"`);

  return { status: "sent", message };
};

// 🔊 Convert AI-Generated Message to Speech (Voice Note)
const convertToVoiceNote = async (text, debtorId) => {
  const client = new textToSpeech.TextToSpeechClient();
  const request = {
    input: { text },
    voice: { languageCode: "en-US", ssmlGender: "NEUTRAL" },
    audioConfig: { audioEncoding: "MP3" },
  };

  const [response] = await client.synthesizeSpeech(request);
  const filePath = `voice_notes/debtor_${debtorId}.mp3`;
  await util.promisify(fs.writeFile)(filePath, response.audioContent, "binary");

  return filePath;
};

// 📞 Simulated AI Call System
const makeAICall = async (debtor) => {
  console.log(`📞 AI calling debtor: ${debtor.name} at ${debtor.phone}`);
  return `Call placed to ${debtor.phone}`;
};

// 💬 AI-Generated WhatsApp Message
const sendWhatsAppMessage = async (debtor) => {
  const task = "Debt Collection WhatsApp";
  const prompt = `Generate a polite yet firm debt reminder for ${debtor.name} who owes $${debtor.amountDue} in WhatsApp-friendly format.`;

  const response = await executeLlama({ prompt, task });
  const message = response.response.trim();

  console.log(`💬 Sending WhatsApp message to ${debtor.phone}: "${message}"`);

  return { status: "sent", message };
};

// 📩 📞 🔊 Debt Collection Request
app.post("/api/ai/debt-collection", async (req, res) => {
  const { debtorId, name, phone, amountDue, notifyMethod } = req.query; // Use req.query

  if (!debtorId || !name || !phone || !amountDue || !notifyMethod) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const debtor = { debtorId, name, phone, amountDue };
  let response = { status: "success" };

  try {
    if (notifyMethod === "sms") {
      response.sms = await sendDebtReminderSMS(debtor);
    } else if (notifyMethod === "voice") {
      response.voiceNote = await convertToVoiceNote(
        `Dear ${name}, you have an outstanding balance of $${amountDue}. Kindly clear it.`,
        debtorId
      );
    } else if (notifyMethod === "call") {
      response.call = await makeAICall(debtor);
    } else if (notifyMethod === "whatsapp") {
      response.whatsapp = await sendWhatsAppMessage(debtor);
    } else {
      return res.status(400).json({ error: "Invalid notification method" });
    }

    res.json(response);
  } catch (error) {
    res.status(500).json({ error: "Debt collection failed", details: error.message });
  } 
});
// AI-Powered Credit Score Estimation
app.post("/api/banking/credit-score", logRequest, (req, res) => {
  handleAIRequest(req, res, "credit-score-estimation", (body) => {
    const { financialHistory } = body;
    if (!financialHistory) {
      throw new Error("Financial history data is required");
    }
    return `Estimate the credit score based on this financial history: ${JSON.stringify(financialHistory)}. Provide a score out of 850.`;
  });
});

// AI-Powered Post Optimization
app.post("/api/social/optimal-post-time", logRequest, (req, res) => {
  handleAIRequest(req, res, "post-optimization", (body) => {
    const { userActivityData } = body;
    if (!userActivityData) {
      throw new Error("User activity data is required");
    }
    return `Analyze this user activity data: ${JSON.stringify(userActivityData)}. Suggest the best time to post for maximum engagement.`;
  });
});

// AI-Powered Fake News Detection
app.post("/api/social/fake-news-detection", logRequest, (req, res) => {
  handleAIRequest(req, res, "fake-news-detection", (body) => {
    const { articleText } = body;
    if (!articleText) {
      throw new Error("Article text is required");
    }
    return `Analyze this article: "${articleText}". Determine if it contains false or misleading information (yes or no) and provide reasoning.`;
  });
});

// AI-Powered Text Summarization
app.post("/api/nlp/summarize-text", logRequest, (req, res) => {
  handleAIRequest(req, res, "text-summarization", (body) => {
    const { text } = body;
    if (!text) {
      throw new Error("Text is required");
    }
    return `Summarize the following text into key points: "${text}".`;
  });
});

// AI-Powered Language Translation
app.post("/api/nlp/translate", logRequest, (req, res) => {
  handleAIRequest(req, res, "language-translation", (body) => {
    const { text, targetLanguage } = body;
    if (!text || !targetLanguage) {
      throw new Error("Text and target language are required");
    }
    return `Translate this text: "${text}" into ${targetLanguage}.`;
  });
});

// AI-Powered Speech-to-Text
app.post("/api/nlp/speech-to-text", logRequest, (req, res) => {
  handleAIRequest(req, res, "speech-to-text", (body) => {
    const { audioData } = body;
    if (!audioData) {
      throw new Error("Audio data is required");
    }
    return `Convert this speech data into text: "${audioData}".`;
  });
});

// AI Routes
app.post("/api/ai/analyze-data", logRequest, validateRequest(["dataset", "question"]), (req, res) => {
  handleAIRequest(req, res, "data-analysis", (body) => `Analyze this dataset and answer: ${body.question}\n${JSON.stringify(body.dataset)}`);
});

app.post("/api/ai/grammar-check", logRequest, validateRequest(["text"]), (req, res) => {
  handleAIRequest(req, res, "grammar-correction", (body) => `Correct the grammar in: ${body.text}`);
});

app.post("/api/ai/chatbot", logRequest, validateRequest(["message"]), (req, res) => {
  handleAIRequest(req, res, "chatbot", (body) => body.message);
});

app.post("/api/ai/text-to-video", logRequest, validateRequest(["text"]), async (req, res) => {
  try {
    const prompt = `Generate a video for: \"${req.body.text}\"`;
    const response = await executeLlama({ prompt, task: "text-to-video", n: 1, maxTokens: 256, temperature: 0.7, topK: 50, nThreads: 3 });
    if (!response || !response.response.trim()) {
      return res.status(500).json({ error: "Failed to generate video" });
    }
    const filePath = path.join(__dirname, "generated_videos", `video_${Date.now()}.txt`);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, response.response.trim(), "utf8");
    res.json({ status: "success", videoDescription: response.response.trim(), savedPath: filePath });
  } catch (error) {
    handleError(res, error, "Text-to-video request failed");
  }
});

// AI-Powered Sentiment Analysis
app.post("/api/social/sentiment-analysis", logRequest, validateRequest(["text"]), (req, res) => {
  handleAIRequest(req, res, "sentiment-analysis", (body) => `Analyze sentiment: \"${body.text}\".`);
});

// AI-Powered Fake News Detection
app.post("/api/social/fake-news-detection", logRequest, validateRequest(["articleText"]), (req, res) => {
  handleAIRequest(req, res, "fake-news-detection", (body) => `Analyze if this article contains fake news: \"${body.articleText}\".`);
});

// AI-Powered Hashtag Recommendation
app.post("/api/social/recommend-hashtags", async (req, res) => {
  try {
    // Accept content from either query params or body
    const content = req.body.content || req.query.content;
    if (!content) {
      return res.status(400).json({ error: "Content is required" });
    }

    const prompt = `Suggest three relevant hashtags for: "${content}".`;
    
    // Ensure `executeLlama` runs properly
    const response = await executeLlama({ prompt, task: "hashtag-recommendation" });

    if (!response || !response.response) {
      throw new Error("Invalid response from AI model");
    }

    // Parse and sanitize hashtags
    let hashtags = response.response.trim().split(/,\s*/).map(tag => tag.startsWith("#") ? tag : `#${tag}`);

    res.json({ status: "success", hashtags });
  } catch (error) {
    console.error("Hashtag recommendation error:", error);
    res.status(500).json({ error: "Hashtag recommendation failed", details: error.message });
  }
});

// AI-Powered Post Scheduling Suggestion
app.post("/api/social/suggest-post-time", async (req, res) => {
  try {
    const content = req.body.content || req.query.content;
    const platform = req.body.platform || req.query.platform;

    if (!content || !platform) {
      return res.status(400).json({ error: "Content and platform are required" });
    }

    const prompt = `Suggest the best posting time on ${platform} for: "${content}".`;
    const response = await executeLlama({ prompt, task: "post-scheduling" });

    if (!response || !response.response) {
      throw new Error("Invalid response from AI model");
    }

    res.json({ status: "success", bestTime: response.response.trim() });
  } catch (error) {
    console.error("Post scheduling error:", error);
    res.status(500).json({ error: "Post scheduling suggestion failed", details: error.message });
  }
});

// AI-Powered Automated Replies
app.post("/api/social/auto-reply", async (req, res) => {
  try {
    const message = req.body.message || req.query.message;

    if (!message) {
      return res.status(400).json({ error: "Message is required" });
    }

    const prompt = `Generate a reply to: "${message}".`;
    const response = await executeLlama({ prompt, task: "auto-reply" });

    if (!response || !response.response) {
      throw new Error("Invalid response from AI model");
    }

    res.json({ status: "success", reply: response.response.trim() });
  } catch (error) {
    console.error("Auto-reply error:", error);
    res.status(500).json({ error: "Auto-reply generation failed", details: error.message });
  }
});
// AI-Powered Image Captioning
app.post("/api/social/generate-caption", logRequest, (req, res) => {
  handleAIRequest(req, res, "image-captioning", (body) => {
    const imageUrl = body.imageUrl || req.query.imageUrl;
    if (!imageUrl) {
      throw new Error("Image URL is required");
    }
    return `Describe this image: "${imageUrl}".`;
  });
}); 

// AI-Powered Trend Analysis
app.post("/api/social/analyze-trends", logRequest, (req, res) => {
  handleAIRequest(req, res, "trend-analysis", (body) => {
    const topic = body.topic || req.query.topic;
    if (!topic) {
      throw new Error("Topic is required");
    }
    return `Analyze social media trends on: "${topic}".`;
  });
});

// AI-Powered Credit Score Estimation
app.post("/api/banking/credit-score", logRequest, (req, res) => {
  handleAIRequest(req, res, "credit-score-estimation", (body) => {
    const { financialHistory } = body;
    if (!financialHistory) {
      throw new Error("Financial history data is required");
    }
    return `Estimate the credit score based on this financial history: ${JSON.stringify(financialHistory)}. Provide a score out of 850.`;
  });
});

// AI-Powered Post Optimization
app.post("/api/social/optimal-post-time", logRequest, (req, res) => {
  handleAIRequest(req, res, "post-optimization", (body) => {
    const { userActivityData } = body;
    if (!userActivityData) {
      throw new Error("User activity data is required");
    }
    return `Analyze this user activity data: ${JSON.stringify(userActivityData)}. Suggest the best time to post for maximum engagement.`;
  });
});

// AI-Powered Fake News Detection
app.post("/api/social/fake-news-detection", logRequest, (req, res) => {
  handleAIRequest(req, res, "fake-news-detection", (body) => {
    const { articleText } = body;
    if (!articleText) {
      throw new Error("Article text is required");
    }
    return `Analyze this article: "${articleText}". Determine if it contains false or misleading information (yes or no) and provide reasoning.`;
  });
});

// AI-Powered Text Summarization
app.post("/api/nlp/summarize-text", logRequest, (req, res) => {
  handleAIRequest(req, res, "text-summarization", (body) => {
    const { text } = body;
    if (!text) {
      throw new Error("Text is required");
    }
    return `Summarize the following text into key points: "${text}".`;
  });
});

// AI-Powered Language Translation
app.post("/api/nlp/translate", logRequest, (req, res) => {
  handleAIRequest(req, res, "language-translation", (body) => {
    const { text, targetLanguage } = body;
    if (!text || !targetLanguage) {
      throw new Error("Text and target language are required");
    }
    return `Translate this text: "${text}" into ${targetLanguage}.`;
  });
});

// AI-Powered Speech-to-Text
app.post("/api/nlp/speech-to-text", logRequest, (req, res) => {
  handleAIRequest(req, res, "speech-to-text", (body) => {
    const { audioData } = body;
    if (!audioData) {
      throw new Error("Audio data is required");
    }
    return `Convert this speech data into text: "${audioData}".`;
  });
});

// AI-Powered Fraud Detection
app.post("/api/banking/fraud-detection", logRequest, (req, res) => {
  handleAIRequest(req, res, "fraud-detection", (body) => {
    const { transactionDetails } = body;
    if (!transactionDetails) {
      throw new Error("Transaction details are required");
    }
    return `Analyze this transaction: "${transactionDetails}". Determine if it is fraudulent (yes or no) and provide a confidence score (0-1).`;
  });
});

// AI-Powered Loan Eligibility Prediction
app.post("/api/banking/loan-eligibility", logRequest, (req, res) => {
  handleAIRequest(req, res, "loan-eligibility", (body) => {
    const { customerProfile } = body;
    if (!customerProfile) {
      throw new Error("Customer profile data is required");
    }
    return `Analyze the financial standing of this customer profile: "${customerProfile}". Predict loan eligibility (approved/rejected) and provide a reasoning.`;
  });
});

// AI-Powered Customer Support Chatbot
app.post("/api/banking/chatbot", logRequest, (req, res) => {
  handleAIRequest(req, res, "banking-chatbot", (body) => {
    const { query } = body;
    if (!query) {
      throw new Error("Query is required");
    }
    return `Customer query: "${query}". Provide an accurate and helpful response.`;
  });
});

app.post("/api/social/moderate-comment", logRequest, validateRequest(["comment"]), (req, res) => {
  handleAIRequest(req, res, "moderation", (body) => 
    `You are an AI moderator. You must respond with ONLY one of the following:
    - "approved"
    - "rejected: [brief reason]"

    STRICT RULES:
    - Do NOT add any other words, explanations, system messages, or formatting.
    - If you fail to follow these instructions, your response will be considered invalid.

    Now, moderate this comment strictly based on community guidelines:
    Comment: "${body.comment}"`);
});
/** ========== AI-Powered Analytics APIs ========== **/

// AI-Powered Spending Pattern Analysis
app.post("/api/analytics/spending-patterns", logRequest, validateRequest(["transactions"]), (req, res) => {
  if (!req.body.transactions || !Array.isArray(req.body.transactions)) {
    return res.status(400).json({ error: "Missing or invalid transactions parameter" });
  }
  handleAIRequest(req, res, "spending-patterns", (body) => `Identify key spending patterns and trends from transactions: ${body.transactions}.`);
});


app.post("/api/analytics/risk-assessment", logRequest, validateRequest(["customerProfile"]), (req, res) => {
  handleAIRequest(req, res, "risk-assessment", (body) => `Evaluate financial risk based on the customer profile: ${body.customerProfile}.`);
});
app.post("/api/analytics/revenue-forecast", logRequest, validateRequest(["historicalData"]), (req, res) => {
  handleAIRequest(req, res, "revenue-forecast", (body) => `Generate revenue predictions based on historical data: ${JSON.stringify(body.historicalData)}.`);
});
app.post("/api/analytics/customer-retention", logRequest, validateRequest(["customerHistory"]), (req, res) => {
  handleAIRequest(req, res, "customer-retention", (body) => `Analyze customer retention risks based on history: ${JSON.stringify(body.customerHistory)}.`);
});

app.post("/api/analytics/customer-retention", logRequest, validateRequest(["customerHistory"]), (req, res) => {
  handleAIRequest(req, res, "customer-retention", (body) => `Analyze customer retention risks based on history: ${JSON.stringify(body.customerHistory)}.`);
});
// AI-Powered Fraud Detection
app.post("/api/banking/fraud-detection", logRequest, (req, res) => {
  handleAIRequest(req, res, "fraud-detection", (body) => {
    const { transactionDetails } = body;
    if (!transactionDetails) {
      throw new Error("Transaction details are required");
    }
    return `Analyze this transaction: "${transactionDetails}". Determine if it is fraudulent (yes or no) and provide a confidence score (0-1).`;
  });
});

// AI-Powered Loan Eligibility Prediction
app.post("/api/banking/loan-eligibility", logRequest, (req, res) => {
  handleAIRequest(req, res, "loan-eligibility", (body) => {
    const { customerProfile } = body;
    if (!customerProfile) {
      throw new Error("Customer profile data is required");
    }
    return `Analyze the financial standing of this customer profile: "${customerProfile}". Predict loan eligibility (approved/rejected) and provide a reasoning.`;
  });
});

// AI-Powered Customer Support Chatbot
app.post("/api/banking/chatbot", logRequest, (req, res) => {
  handleAIRequest(req, res, "banking-chatbot", (body) => {
    const { query } = body;
    if (!query) {
      throw new Error("Query is required");
    }
    return `Customer query: "${query}". Provide an accurate and helpful response.`;
  });
});

app.post("/api/social/moderate-comment", logRequest, validateRequest(["comment"]), (req, res) => {
  handleAIRequest(req, res, "moderation", (body) => 
    `You are an AI moderator. You must respond with ONLY one of the following:
    - "approved"
    - "rejected: [brief reason]"

    STRICT RULES:
    - Do NOT add any other words, explanations, system messages, or formatting.
    - If you fail to follow these instructions, your response will be considered invalid.

    Now, moderate this comment strictly based on community guidelines:
    Comment: "${body.comment}"`);
});
/** ========== AI-Powered Analytics APIs ========== **/



app.post("/api/analytics/risk-assessment", logRequest, validateRequest(["customerProfile"]), (req, res) => {
  handleAIRequest(req, res, "risk-assessment", (body) =>
    `Evaluate financial risk based on the customer profile: ${JSON.stringify(body.customerProfile)}.`
  );
});





let latestAnalytics = {}; // Store latest analytics for real-time updates
// 📊 Customer Retention Analysis with Enhanced Insights
app.post("/api/analytics/customer-retention", logRequest, validateRequest(["transactions", "customerHistory"]), async (req, res) => {
  const task = "Customer Retention Analysis";

  const promptTemplate = (data) => {
    const { transactions, customerHistory } = data;
    if (!Array.isArray(transactions) || !Array.isArray(customerHistory)) return "";

    const totalCustomers = customerHistory.length;
    const retainedCustomers = transactions.filter(transaction =>
      customerHistory.some(customer => customer.id === transaction.customerId)
    ).length;
    const retentionRate = totalCustomers > 0 ? (retainedCustomers / totalCustomers) * 100 : 0;

    return `Analyze customer retention: Total Customers - ${totalCustomers}, Retained Customers - ${retainedCustomers}, Retention Rate - ${retentionRate.toFixed(2)}%. Provide churn risk and retention strategies.`;
  };

  try {
    const startTime = Date.now();
    const prompt = promptTemplate(req.body);

    if (!prompt) {
      return res.status(400).json({ error: "Invalid data", details: "Missing or incorrect input format." });
    }

    console.log(`🔄 Processing AI task: ${task} | Prompt: "${prompt}"`);

    const aiResponse = await executeLlama({ prompt, task });

    if (!aiResponse || !aiResponse.response) {
      return res.status(500).json({ error: "AI response is empty", details: aiResponse });
    }

    const executionTime = Date.now() - startTime;
    const responseText = aiResponse.response.trim();

    // ** Extract Customer Retention Data **
    const totalCustomers = req.body.customerHistory.length;
    const retainedCustomers = req.body.transactions.filter(transaction =>
      req.body.customerHistory.some(customer => customer.id === transaction.customerId)
    ).length;
    const retentionRate = totalCustomers > 0 ? (retainedCustomers / totalCustomers) * 100 : 0;
    const churnRisk = retentionRate < 50 ? "High" : retentionRate < 75 ? "Medium" : "Low";

    // ** Bar Chart for Retention vs Churn **
    const retentionChartUrl = ChartJSImage()
      .chart({
        type: "bar",
        data: {
          labels: ["Retained Customers", "Churned Customers"],
          datasets: [{
            label: "Customer Retention",
            data: [retainedCustomers, totalCustomers - retainedCustomers],
            backgroundColor: ["#4CAF50", "#FF5733"],
          }],
        },
        options: { responsive: true }
      })
      .backgroundColor("white")
      .width(600)
      .height(300)
      .toURL();

    // ** Pie Chart for Retention Distribution **
    const pieChartUrl = ChartJSImage()
      .chart({
        type: "pie",
        data: {
          labels: ["Retained Customers", "Churned Customers"],
          datasets: [{
            data: [retainedCustomers, totalCustomers - retainedCustomers],
            backgroundColor: ["#36A2EB", "#FFCE56"],
          }],
        },
        options: { responsive: true }
      })
      .backgroundColor("white")
      .width(600)
      .height(300)
      .toURL();

    // ** Update Latest Analytics Data **
    latestAnalytics.retention = {
      totalCustomers,
      retainedCustomers,
      retentionRate,
      churnRisk,
      retentionStrategy: responseText,
      executionTime,
      charts: {
        barChart: retentionChartUrl,
        pieChart: pieChartUrl,
      }
    };

    // Emit real-time analytics update
    io.emit("analyticsUpdate", latestAnalytics);

    res.json({
      status: "success",
      analytics: latestAnalytics.retention,
      response: responseText,
      executionTime,
    });

  } catch (error) {
    console.error("Error in customer retention analysis:", error);
    res.status(500).json({ error: error.message || "Internal Server Error" });
  }
});
 


app.post("/api/banking/fraud-detection", logRequest, validateRequest(["transactionDetails"]), async (req, res) => {
  try {
    const { transactionDetails } = req.body;

    console.log(`🔄 Processing AI Task: Fraud Detection...`);

    const aiResponse = await handleAIRequest(req, res, "fraud-detection", (query) =>
      `Analyze this transaction: "${query.transactionDetails}". Determine if it is fraudulent (yes or no) and provide a confidence score (0-1).`
    );

    if (!aiResponse || !aiResponse.response) {
      return res.status(500).json({ error: "AI response is empty", details: aiResponse });
    }

    const fraudDetected = aiResponse.response.includes("yes");
    const confidenceScore = parseFloat(aiResponse.response.match(/\d+(\.\d+)?/g)?.[0] || "0");

    // ** Bar Chart: Fraud vs Non-Fraud Transactions **
    const fraudChart = ChartJSImage()
      .chart({
        type: "bar",
        data: {
          labels: ["Fraudulent", "Non-Fraudulent"],
          datasets: [{
            label: "Transaction Analysis",
            data: [fraudDetected ? 1 : 0, fraudDetected ? 0 : 1],
            backgroundColor: [fraudDetected ? "#FF0000" : "#4CAF50", fraudDetected ? "#4CAF50" : "#FF0000"],
          }],
        },
        options: { responsive: true }
      })
      .backgroundColor("white")
      .width(600)
      .height(300)
      .toURL();

    // ** Pie Chart: Fraud Confidence Score **
    const pieChart = ChartJSImage()
      .chart({
        type: "pie",
        data: {
          labels: ["Fraud Risk", "Safe"],
          datasets: [{
            data: [confidenceScore * 100, 100 - (confidenceScore * 100)],
            backgroundColor: ["#FF0000", "#4CAF50"],
          }],
        },
        options: { responsive: true }
      })
      .backgroundColor("white")
      .width(600)
      .height(300)
      .toURL();

    // ** Store Fraud Analysis Data **
    latestAnalytics.fraud = {
      fraudDetected,
      confidenceScore,
      fraudChart,
      pieChart,
    };

    // Emit real-time analytics update
    io.emit("analyticsUpdate", latestAnalytics);

    res.json({
      status: "success",
      analytics: latestAnalytics.fraud,
      response: aiResponse.response,
    });

  } catch (error) {
    console.error("Error in fraud detection:", error);
    res.status(500).json({ error: error.message });
  }
});




// 📊 Spending Patterns Analysis
app.post("/api/analytics/spending-patterns", logRequest, validateRequest(["transactions"]), async (req, res) => {
  const task = "Spending Patterns Analysis";

  const promptTemplate = (data) => {
    if (!Array.isArray(data.transactions)) return "";

    const categoryMap = {};
    data.transactions.forEach(({ category, amount }) => {
      categoryMap[category] = (categoryMap[category] || 0) + amount;
    });

    return `Analyze spending trends from transactions: ${JSON.stringify(categoryMap)}. Identify key spending patterns and insights.`;
  };

  try {
    const startTime = Date.now();
    const prompt = promptTemplate(req.body);

    if (!prompt) {
      return res.status(400).json({ error: "Invalid data", details: "Missing or incorrect input format." });
    }

    console.log(`🔄 Processing AI task: ${task} | Prompt: "${prompt}"`);

    const aiResponse = await executeLlama({ prompt, task });

    if (!aiResponse || !aiResponse.response) {
      return res.status(500).json({ error: "AI response is empty", details: aiResponse });
    }

    const executionTime = Date.now() - startTime;
    const responseText = aiResponse.response.trim();

    // ** Aggregate Spending Data **
    const categoryMap = {};
    req.body.transactions.forEach(({ category, amount }) => {
      categoryMap[category] = (categoryMap[category] || 0) + amount;
    });

    const labels = Object.keys(categoryMap);
    const values = Object.values(categoryMap);

    // ** Bar Chart for Spending Categories **
    const barChartUrl = ChartJSImage()
      .chart({
        type: "bar",
        data: {
          labels,
          datasets: [{ label: "Spending Analysis", data: values, backgroundColor: "#4CAF50" }],
        },
        options: { responsive: true },
      })
      .backgroundColor("white")
      .width(600)
      .height(300)
      .toURL();

    // ** Pie Chart for Spending Distribution **
    const pieChartUrl = ChartJSImage()
      .chart({
        type: "pie",
        data: {
          labels,
          datasets: [{ data: values, backgroundColor: ["#36A2EB", "#FFCE56", "#FF5733", "#4CAF50", "#9B59B6"] }],
        },
        options: { responsive: true },
      })
      .backgroundColor("white")
      .width(600)
      .height(300)
      .toURL();

    // ** Update Latest Analytics Data **
    latestAnalytics.spending = {
      totalTransactions: req.body.transactions.length,
      spendingByCategory: categoryMap,
      insights: responseText,
      executionTime,
      charts: { barChart: barChartUrl, pieChart: pieChartUrl },
    };

    // Emit real-time analytics update
    io.emit("analyticsUpdate", latestAnalytics);

    res.json({
      status: "success",
      analytics: latestAnalytics.spending,
      response: responseText,
      executionTime,
    });

  } catch (error) {
    console.error("Error in spending patterns analysis:", error);
    res.status(500).json({ error: error.message || "Internal Server Error" });
  }
});

// ⚠️ Risk Assessment Analysis
app.post("/api/analytics/risk-assessment", logRequest, validateRequest(["customerProfile"]), async (req, res) => {
  const task = "Risk Assessment Analysis";

  const promptTemplate = (data) => {
    if (!data.customerProfile) return "";
    return `Evaluate financial risk based on the customer profile: ${JSON.stringify(data.customerProfile)}. Provide a risk score and mitigation strategies.`;
  };

  try {
    const startTime = Date.now();
    const prompt = promptTemplate(req.body);

    if (!prompt) {
      return res.status(400).json({ error: "Invalid data", details: "Missing or incorrect input format." });
    }

    console.log(`🔄 Processing AI task: ${task} | Prompt: "${prompt}"`);

    const aiResponse = await executeLlama({ prompt, task });

    if (!aiResponse || !aiResponse.response) {
      return res.status(500).json({ error: "AI response is empty", details: aiResponse });
    }

    const executionTime = Date.now() - startTime;
    const responseText = aiResponse.response.trim();

    // ** Risk Level Analysis **
    const riskScore = Math.floor(Math.random() * 100); // Simulated AI-driven risk score
    const riskLevel = riskScore > 75 ? "High" : riskScore > 50 ? "Medium" : "Low";

    // ** Bar Chart for Risk Score **
    const barChartUrl = ChartJSImage()
      .chart({
        type: "bar",
        data: {
          labels: ["Risk Score"],
          datasets: [{ label: "Risk Level", data: [riskScore], backgroundColor: "#FF5733" }],
        },
        options: { responsive: true },
      })
      .backgroundColor("white")
      .width(600)
      .height(300)
      .toURL();

    // ** Update Latest Analytics Data **
    latestAnalytics.risk = {
      customerProfile: req.body.customerProfile,
      riskScore,
      riskLevel,
      mitigationStrategies: responseText,
      executionTime,
      charts: { barChart: barChartUrl },
    };

    // Emit real-time analytics update
    io.emit("analyticsUpdate", latestAnalytics);

    res.json({
      status: "success",
      analytics: latestAnalytics.risk,
      response: responseText,
      executionTime,
    });

  } catch (error) {
    console.error("Error in risk assessment analysis:", error);
    res.status(500).json({ error: error.message || "Internal Server Error" });
  }
});
// 📈 Revenue Forecast Analysis with Enhanced Insights
app.post("/api/analytics/revenue-forecast", logRequest, validateRequest(["historicalData"]), async (req, res) => {
  const task = "Revenue Forecast Analysis";

  const promptTemplate = (data) => {
    if (!Array.isArray(data.historicalData)) return "";
    return `Generate revenue predictions based on historical data: ${JSON.stringify(data.historicalData)}. Provide estimated revenue growth, trends, and confidence intervals.`;
  };
 
  try {
    const startTime = Date.now();
    const prompt = promptTemplate(req.body);

    if (!prompt) {
      return res.status(400).json({ error: "Invalid data", details: "Missing or incorrect input format." });
    }

    console.log(`🔄 Processing AI task: ${task} | Prompt: "${prompt}"`);

    const aiResponse = await executeLlama({ prompt, task });

    if (!aiResponse || !aiResponse.response) {
      return res.status(500).json({ error: "AI response is empty", details: aiResponse });
    }

    const executionTime = Date.now() - startTime;
    const responseText = aiResponse.response.trim();

    // ** Extract historical revenue data **
    const historicalData = req.body.historicalData;
    const totalRevenue = historicalData.reduce((sum, record) => sum + record.revenue, 0);
    const revenueList = historicalData.map((r) => r.revenue);
    
    // ** Moving Average Calculation for Trends **
    const movingAvg = revenueList.reduce((a, b) => a + b, 0) / revenueList.length;

    // ** Simulated AI-driven Growth Rate with Confidence Interval **
    const avgGrowthRate = (Math.random() * 10) + 5; // 5-15% range
    const projectedRevenue = totalRevenue * (1 + avgGrowthRate / 100);
    const minProjectedRevenue = projectedRevenue * 0.95; // 5% lower bound
    const maxProjectedRevenue = projectedRevenue * 1.05; // 5% upper bound

    // ** YoY Growth Rate Calculation **
    const lastYearRevenue = historicalData.length > 1 ? historicalData[historicalData.length - 2].revenue : totalRevenue * 0.9;
    const yoyGrowthRate = ((totalRevenue - lastYearRevenue) / lastYearRevenue) * 100;

    // ** Line Chart for Revenue Trends **
    const lineChartUrl = ChartJSImage()
      .chart({
        type: "line",
        data: {
          labels: ["Current Revenue", "Projected Revenue"],
          datasets: [{ label: "Revenue Forecast", data: [totalRevenue, projectedRevenue], borderColor: "#36A2EB" }],
        },
        options: { responsive: true },
      })
      .backgroundColor("white")
      .width(600)
      .height(300)
      .toURL();

    // ** Bar Chart for Historical vs Forecasted Revenue **
    const barChartUrl = ChartJSImage()
      .chart({
        type: "bar",
        data: {
          labels: ["Last Year", "Current Year", "Projected"],
          datasets: [
            {
              label: "Revenue Comparison",
              data: [lastYearRevenue, totalRevenue, projectedRevenue],
              backgroundColor: ["#FF5733", "#36A2EB", "#4CAF50"],
            },
          ],
        },
        options: { responsive: true },
      })
      .backgroundColor("white")
      .width(600)
      .height(300)
      .toURL();

    // ** Update Latest Analytics Data **
    latestAnalytics.revenue = {
      totalRevenue,
      movingAvg,
      avgGrowthRate,
      projectedRevenue,
      minProjectedRevenue,
      maxProjectedRevenue,
      yoyGrowthRate,
      forecastInsights: responseText,
      executionTime,
      charts: { lineChart: lineChartUrl, barChart: barChartUrl },
    };

    // Emit real-time analytics update
    io.emit("analyticsUpdate", latestAnalytics);

    res.json({
      status: "success",
      analytics: latestAnalytics.revenue,
      response: responseText,
      executionTime,
    });

  } catch (error) {
    console.error("Error in revenue forecast analysis:", error);
    res.status(500).json({ error: error.message || "Internal Server Error" });
  }
});


// Ensure Express JSON middleware is enabled
app.use(express.json());
// Swagger configuration
// Swagger definition
const swaggerSpec = swaggerJsdoc({
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Node.js Swagger API',
      version: '1.0.0',
      description: 'Test API with Swagger UI',
    },
    servers: [
      {
        url: 'http://localhost:3000',  // Local development server URL
        description: 'Local Development Server',  // Optional description
      },
      {
        url: 'https://backend-email-otp-backend-wzo6.onrender.com',  // Production server URL
        description: 'Production Server',  // Optional description
      },
    ],
  },
  apis: ['./index.js'], // JSDoc comments live here
});

// Serve Swagger docs at /docs/swagger
app.use('/docs/swagger', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Example route with Swagger doc
/**
 * @swagger
 * /hello:
 *   get:
 *     summary: Returns a hello message
 *     responses:
 *       200:
 *         description: Successful response
 */
app.get('/hello', (req, res) => {
  res.send({ message: 'Hello from Swagger API' });
});

// Swagger UI setup
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Start the main server
app.listen(PORT, async () => {
  try {
    console.log(`Main server is running on port ${PORT}`);

    // Set up the AI model asynchronously
    await setupModel(4000);

    // Wait for AI model server to be ready
    await waitForServer('http://localhost:4000', 5, 2000);

    console.log('AI model setup completed successfully!');
  } catch (error) {
    console.error('Error setting up AI model:', error);
    process.exit(1);
  }
});
