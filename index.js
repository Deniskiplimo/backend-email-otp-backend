require('dotenv').config();
const { generateCode, summarizeText, translateText } = require('./generalLlama');
const moment = require("moment");
const { generateCodeWithCodeLlama } = require('./codeLlama');
const path = require('path');
const { llamacpp, streamText } = require("modelfusion");
const ip = '8.8.8.8';
const http = require("http");
const { Server } = require("socket.io");
const ChartJSImage = require("chart.js-image"); // Generate graphs in backend
const { Worker } = require("worker_threads");
const WebSocket = require("ws");
const open = require("open");
const crypto = require("crypto");
const NodeCache = require("node-cache");
const { graphqlHTTP } = require("express-graphql"); 
const { buildSchema } = require("graphql");
const cache = new NodeCache({ stdTTL: 300 }); // Cache responses for 5 minutes
const os = require('os');
const { body, validationResult ,query} = require("express-validator");
const PORT = 8000;
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
const { spawn,exec,execSync } = require('child_process');
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
const server = http.createServer(app);
const transport = new winston.transports.DailyRotateFile({
  filename: 'logs/%DATE%-results.log', // Log file name pattern
  datePattern: 'YYYY-MM-DD',           // Date format for the filename
  zippedArchive: true,                 // Whether to compress old logs
  maxSize: '20m',                      // Max file size before rotation
  maxFiles: '14d'                      // Keep logs for 14 days
});
const io = new Server(server, { cors: { origin: "*" } });
// First, create the server using `app`

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
const LLAMA_FILE_WIN = "llamafile.exe";
const LLAMA_FILE_LINUX = "llamafile";
const MODEL_FILE = "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";

// ✅ Get platform-specific filenames
const llamaFile = process.platform === "win32" ? LLAMA_FILE_WIN : LLAMA_FILE_LINUX;

// ✅ Helper function to download files
async function downloadFile(url, outputPath) {
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
    process.stdout.write(`Downloaded ${(downloadedLength / totalLength * 100).toFixed(2)}%\r`);
  });

  response.data.pipe(writer);

  return new Promise((resolve, reject) => {
    writer.on("finish", () => {
      console.log(`\n✅ Download of ${outputPath} completed.`);
      if (process.platform !== "win32") fs.chmodSync(outputPath, 0o755); // Add execute permission on Linux/Mac
      resolve();
    });
    writer.on("error", reject);
  });
}

// ✅ Kill previous Llama instances
function killPreviousLlama() {
  try {
    if (process.platform === "win32") {
      execSync("taskkill /IM llamafile.exe /F", { stdio: "ignore" }); // Windows
    } else {
      execSync("pkill -f llamafile", { stdio: "ignore" }); // Linux/macOS
    }
  } catch (err) {
    console.log("No previous Llama instance found.");
  }
}

// ✅ Function to start the AI server
async function setupModel(port) {
  try {
    await downloadFile(
      "https://github.com/Mozilla-Ocho/llamafile/releases/download/0.6/llamafile-0.6",
      llamaFile
    );
    await downloadFile(
      "https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
      MODEL_FILE
    );

    console.log(`🚀 Starting AI server on port ${port}...`);

    const command = process.platform === "win32"
      ? `${llamaFile} -m ${MODEL_FILE} --nobrowser --port ${port}`
      : `./${llamaFile} -m ${MODEL_FILE} --nobrowser --port ${port}`;

    const processInstance = exec(command);

    processInstance.stdout.on("data", (data) => {
      console.log(`Llama Output: ${data}`);
    });

    processInstance.stderr.on("data", (data) => {
      console.error(`Llama Error: ${data}`);
    });

    await waitForServer(`http://localhost:${port}`);

    console.log(`✅ Llama server started successfully on port ${port}`);
  } catch (error) {
    console.error("❌ Setup error:", error);
    throw error;
  }
}

module.exports = { setupModel, killPreviousLlama };

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

const wss = new WebSocket.Server({ port: PORT });

console.log(`🚀 WebSocket AI Server running on ws://localhost:${PORT}`);

const nThreadsDefault = Math.min(8, os.cpus().length);


const analytics = {
  connections: 0,
  requestCount: 0,
  errorCount: 0,
  executionTimes: [],
  taskStats: {},
  minExecutionTime: null,
  maxExecutionTime: null,
  avgExecutionTime: null,
  rollingAvgExecutionTime: [],
  sentimentCounts: { positive: 0, negative: 0, neutral: 0 },
};

// WebSocket Connection Handling
wss.on("connection", (ws) => {
  analytics.connections++;
  console.log(`🔗 New Client Connected | Active Clients: ${analytics.connections}`);

  ws.on("message", async (message) => {
    analytics.requestCount++;
    try {
      const options = JSON.parse(message);
      if (!options.prompt || typeof options.prompt !== "string") {
        return ws.send(JSON.stringify({ error: "Invalid prompt" }));
      }

      console.log("📩 Processing:", options.prompt);

      const startTime = Date.now();
      const response = await executeLlama(options);
      const executionTime = Date.now() - startTime;

      analytics.executionTimes.push(executionTime);
      ws.send(JSON.stringify({ response, executionTime }));

      console.log(`✅ Response Sent in ${executionTime}ms`);
    } catch (error) {
      analytics.errorCount++;
      console.error("❌ Error:", error.message);
      ws.send(JSON.stringify({ error: "Processing failed", details: error.message }));
    }
  });

  ws.on("close", () => {
    analytics.connections--;
    console.log(`❌ Client Disconnected | Active Clients: ${analytics.connections}`);
  });
});

// Function to Execute AI Model via Worker Thread
async function executeLlama(options = {}) {
  try {
    if (!options || typeof options !== "object") {
      throw new Error("Invalid options object");
    }

    const {
      prompt,
      model = "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
      task = "default",
      socket = null,
      maxTokens = 128,
      temperature = 0.6,
      topK = 100,
      topP = 0.9,
      nThreads = Math.min(nThreadsDefault, os.loadavg()[0] > 2 ? 4 : nThreadsDefault),
      stream = false,
    } = options;

    if (!prompt.trim()) {
      return Promise.reject({ message: "Invalid prompt", details: "Prompt must be a non-empty string." });
    }

    // Check Cache First (5-minute expiration)
    const cacheKey = crypto.createHash("sha256").update(JSON.stringify(options)).digest("hex");
    const cachedData = cache.get(cacheKey);
    if (cachedData && Date.now() - cachedData.timestamp < 5 * 60 * 1000) {
      console.log("⚡ Returning Cached Response");
      return cachedData.response;
    }

    // AI Execution using Worker Threads
    const startTime = Date.now();
    const response = await runLlamaWithWorker({ prompt, model, socket, maxTokens, temperature, topK, topP, nThreads, stream });
    const executionTime = Date.now() - startTime;

    // Update Analytics
    analytics.executionTimes.push(executionTime);
    analytics.taskStats[task] = (analytics.taskStats[task] || 0) + 1;
    analytics.minExecutionTime = analytics.minExecutionTime !== null ? Math.min(analytics.minExecutionTime, executionTime) : executionTime;
    analytics.maxExecutionTime = analytics.maxExecutionTime !== null ? Math.max(analytics.maxExecutionTime, executionTime) : executionTime;
    if (analytics.executionTimes.length > 10) analytics.executionTimes.shift();
    analytics.avgExecutionTime = analytics.executionTimes.reduce((a, b) => a + b, 0) / analytics.executionTimes.length;

    // Cache Response
    cache.set(cacheKey, { response, timestamp: Date.now() });

    console.log(`✅ Completed in ${executionTime}ms | Task: ${task} | Total Requests: ${analytics.requestCount}`);
    return response;
  } catch (error) {
    analytics.errorCount++;
    console.error("❌ Execution Error:", error.message || error);
    return Promise.reject({ message: "Execution failed", details: error.message });
  }
}

// Worker Thread for AI Execution
function runLlamaWithWorker(options) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(__filename, { workerData: options });

    worker.on("message", resolve);
    worker.on("error", reject);
    worker.on("exit", (code) => {
      if (code !== 0) reject(new Error(`Worker stopped with exit code ${code}`));
    });
  });
}

// Worker Execution Logic
if (!module.parent && require("worker_threads").isMainThread === false) {
  const { parentPort, workerData } = require("worker_threads");

  async function runLlamaModel({ prompt }) {
    await new Promise((resolve) => setTimeout(resolve, Math.random() * 500 + 200)); // Simulating AI Response Delay
    return { response: `Generated response for: ${prompt}` };
  }

  runLlamaModel(workerData)
    .then((result) => parentPort.postMessage(result))
    .catch((error) => parentPort.postMessage({ error: error.message }));
}
// Centralized Error Handling
const handleError = (res, message, error) => {
  console.error(`❌ ${message}:`, error);
  res.status(500).json({ error: message, details: error.message || error });
};

// Generic AI Request Handler with Analytics Tracking
const handleAIRequest = async (req, res, task, promptTemplate) => {
  try {
    const startTime = Date.now();
    const prompt = promptTemplate(req.body);

    if (!prompt || typeof prompt !== "string" || prompt.trim() === "") {
      return res.status(400).json({ error: "Invalid prompt", details: "Prompt must be a non-empty string." });
    }

    console.log(`🔄 Processing AI task: ${task} | Prompt: "${prompt}"`);

    const response = await executeLlama({ prompt, task });

    if (!response || !response.response || response.response.trim() === "") {
      analytics.errorCount++;
      return res.status(500).json({ error: "AI response is empty", details: response });
    }

    const executionTime = Date.now() - startTime;

    // Update analytics data
    analytics.requestCount++;
    analytics.executionTimes.push(executionTime);
    analytics.taskStats[task] = (analytics.taskStats[task] || 0) + 1;
    analytics.minExecutionTime = Math.min(analytics.minExecutionTime ?? executionTime, executionTime);
    analytics.maxExecutionTime = Math.max(analytics.maxExecutionTime ?? executionTime, executionTime);

    res.json({ status: "success", response: response.response.trim(), executionTime });
  } catch (error) {
    analytics.errorCount++;
    handleError(res, `${task} failed`, error);
  }
};  
// AI Task Handler
const handleAITask = async (req, res, prompt, task, options = {}) => {
  try {
    if (!prompt || typeof prompt !== "string" || prompt.trim() === "") {
      return res.status(400).json({ error: "Invalid prompt", details: "Prompt must be a non-empty string." });
    }

    console.log(`🔄 Processing AI task: ${task} with prompt: "${prompt}"`);

    const startTime = Date.now();
    const response = await executeLlama({ prompt, task, ...options });

    // Handle missing or empty response
    if (!response || !response.response || typeof response.response !== "string" || response.response.trim() === "") {
      console.error("❌ AI model returned an empty or invalid response.");
      return res.status(500).json({ error: "AI model returned an invalid response" });
    }

    console.log(`✅ AI task '${task}' completed in ${Date.now() - startTime}ms`);
    
    return res.json({ status: "success", response: response.response.trim() });

  } catch (error) {
    console.error(`❌ AI task '${task}' failed:`, error);
    return res.status(500).json({ error: `${task} failed`, details: error.message });
  }
};
// Get AI Analytics with Filtering
const getAnalytics = async (req, res) => {
  try {
    const { task, startTime, endTime } = req.query;
    let filteredRequests = analytics.executionTimes.map((time, index) => ({
      task: Object.keys(analytics.taskStats)[index] || "unknown",
      executionTime: time,
      timestamp: Date.now() - time, // Approximation
    }));

    if (task) {
      filteredRequests = filteredRequests.filter((entry) => entry.task === task);
    }

    if (startTime || endTime) {
      const start = startTime ? new Date(startTime).getTime() : 0;
      const end = endTime ? new Date(endTime).getTime() : Date.now();
      filteredRequests = filteredRequests.filter((entry) => entry.timestamp >= start && entry.timestamp <= end);
    }

    const executionTimes = filteredRequests.map((entry) => entry.executionTime);
    const totalRequests = executionTimes.length;
    const totalErrors = analytics.errorCount;
    const avgExecutionTime = totalRequests
      ? executionTimes.reduce((a, b) => a + b, 0) / totalRequests
      : 0;

    const minExecutionTime = executionTimes.length ? Math.min(...executionTimes) : null;
    const maxExecutionTime = executionTimes.length ? Math.max(...executionTimes) : null;
    const variance =
      executionTimes.length > 1
        ? executionTimes.reduce((sum, val) => sum + Math.pow(val - avgExecutionTime, 2), 0) / executionTimes.length
        : 0;

    const stdDeviation = Math.sqrt(variance);

    res.json({
      totalRequests,
      totalErrors,
      avgExecutionTime: avgExecutionTime.toFixed(2),
      minExecutionTime,
      maxExecutionTime,
      stdDeviation: stdDeviation.toFixed(2),
      taskStats: analytics.taskStats,
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch analytics", details: error.message });
  }
};

module.exports = { handleAIRequest, getAnalytics };

async function runLlamaModel({
  prompt,
  model,
  socket,
  maxTokens = 128,
  temperature = 0.6,
  topK = 100,
  nThreads = 8,
  port = PORT,
  retryAttempts = 3, // 🔄 Retry feature
}) {
  return new Promise(async (resolve, reject) => {
    console.log("📝 Running Llama with:", { port, prompt, maxTokens, temperature, topK, nThreads });

    if (!port) {
      return reject({ message: "❌ Port is missing!" });
    }

    let attempt = 0;
    let lastError = null;
    let startTime = Date.now(); // ⏳ Start execution time tracking

    while (attempt < retryAttempts) {
      attempt++;
      console.log(`🔄 Attempt ${attempt} of ${retryAttempts}...`);

      const isServerReady = await checkServerAvailability(port);
      if (!isServerReady) {
        lastError = "❌ Llama server is not available";
        continue; // Retry
      }

      const api = llamacpp.Api({
        baseUrl: `http://localhost:${port}`,
      });

      try {
        const timeout = 5000;
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
            system: "You are an AI assistant helping with programming tasks. Be concise and clear.",
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

        // 🔥 Fix: Ensure aiResponse is a string before trimming
        response = typeof response === "string" ? response.trim() : JSON.stringify(response);

        if (!response) {
          lastError = "❌ AI response is empty";
          continue; // Retry if response is empty
        }

        console.log("✅ AI Response Generated Successfully");

        return resolve({
          status: "success",
          message: "Response generated successfully",
          response,
          executionTime: Date.now() - startTime, // ⏳ Track execution time
        });
      } catch (error) {
        lastError = error.message;
        console.error("❌ Error generating response:", error.message);
      }
    }

    // If all attempts fail, return last error
    reject({ message: "Llama Execution Failed", details: lastError });
  });
}

async function generateImage(prompt, outputPath) {
  try {
    if (!prompt || typeof prompt !== "string" || prompt.trim() === "") {
      console.error("❌ Invalid prompt provided.");
      return false;
    }

    console.log(`🎨 Generating image with prompt: "${prompt}"`);
    
    analytics.requestCount++;
    const startTime = Date.now();

    // Call the AI model using executeLlama
    const response = await executeLlama({ prompt, task: "image-generation" });

    if (!response || !response.imageData) {
      console.error("❌ AI model did not return valid image data.");
      analytics.errorCount++;
      return false;
    }

    // Convert base64 image data to a buffer
    const imageBuffer = Buffer.from(response.imageData, "base64");

    // Save image asynchronously
    await fs.writeFile(outputPath, imageBuffer);
    
    const executionTime = Date.now() - startTime;
    analytics.executionTimes.push(executionTime);

    console.log(`✅ Image successfully generated in ${executionTime}ms and saved to: ${outputPath}`);
    
    return true;
  } catch (error) {
    analytics.errorCount++;
    console.error("❌ Image generation failed:", error);
    return false;
  }
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
  await handleAITask(req, res, `Chatbot response to: '${message}' in context '${context}'`, "chat", { temperature });
});

app.post("/api/ai/generate-sql", async (req, res) => {
  const { description, databaseType, temperature = 0.7 } = req.body;
  if (!description || !databaseType) return res.status(400).json({ error: "Description and databaseType are required" });
  await handleAITask(req, res, `Generate a ${databaseType} SQL query that performs: ${description}`, "sql-generation", { temperature });
});
app.post("/api/social/generate-image", logRequest, async (req, res) => {
  const { prompt } = req.body;

  if (!prompt || typeof prompt !== "string" || prompt.trim() === "") {
    return res.status(400).json({ error: "A valid prompt is required for image generation" });
  }

  const outputPath = path.join(__dirname, "generated-images", `${Date.now()}.png`);

  try {
    const success = await generateImage(prompt, outputPath);
    
    if (!success) {
      throw new Error("Image generation failed");
    }

    return res.json({ status: "success", imagePath: `/generated-images/${path.basename(outputPath)}` });
  } catch (error) {
    console.error("❌ Error generating image:", error);
    return res.status(500).json({ error: "Failed to generate image", details: error.message });
  }
});

app.post("/api/ai/sentiment", async (req, res) => {
  handleAIRequest(req, res, "sentiment-analysis", (body) => {
    const text = body.text;
    if (!text || typeof text !== "string" || text.trim() === "") {
      throw new Error("Text is required");
    }
    return `Classify the sentiment of this text: "${text}"`;
  });
});
// API to Get Analytics
app.get("/api/analytics", (req, res) => {
  // Query parameters can be used to filter the analytics data
  const { task, startTime, endTime } = req.query;
  
  // Logic to generate or retrieve specific analytics data (could be filtered based on task and time range)
  const analyticsData = {
    totalRequests: analytics.totalRequests,
    totalSuccess: analytics.totalSuccess,
    totalErrors: analytics.totalErrors,
    avgExecutionTime: analytics.totalRequests ? (analytics.totalExecutionTime / analytics.totalRequests).toFixed(2) : 0,
    taskSpecificData: task ? `Analytics for task: ${task}` : 'All tasks analytics'
  };

  res.json({
    success: true,
    message: "Analytics data fetched successfully",
    data: analyticsData
  });
});


// API to Get Errors Analytics
app.get("/api/analytics/model", async (req, res) => {
  try {
    console.log("Fetching AI model analytics...");

    const aiResponse = await handleAIRequest(req, res, "analytics-model", () => "Get model analytics.");

    // Ensure AI response is valid
    if (!aiResponse || !aiResponse.response || aiResponse.response.trim() === "") {
      console.error("❌ AI response is empty for /api/analytics/model");
      return res.status(500).json({
        success: false,
        message: "Failed to fetch AI model analytics",
        error: "AI response is empty",
      });
    }

    res.json({
      success: true,
      message: "Model analytics fetched successfully",
      analytics: aiResponse.response.trim(),
    });

  } catch (error) {
    console.error("❌ Error in /api/analytics/model:", error);
    if (!res.headersSent) { // Ensure response is sent only once
      res.status(500).json({
        success: false,
        message: "Internal server error while fetching model analytics",
        error: error.message,
      });
    }
  }
});



// API to Get Model Analytics
app.get("/api/analytics/model", async (req, res) => {
  try {
    console.log("Fetching AI model analytics...");

    const aiResponse = await handleAIRequest(req, res, "analytics-model", () => "Get model analytics.");

    // Ensure AI response is valid
    if (!aiResponse || !aiResponse.response || aiResponse.response.trim() === "") {
      console.error("❌ AI response is empty for /api/analytics/model");
      return res.status(500).json({
        success: false,
        message: "Failed to fetch AI model analytics",
        error: "AI response is empty",
      });
    }

    // Send the success response only once
    res.json({
      success: true,
      message: "Model analytics fetched successfully",
      analytics: aiResponse.response.trim(),
    });

  } catch (error) {
    // Check if response was already sent
    if (!res.headersSent) {
      console.error("❌ Error in /api/analytics/model:", error);
      res.status(500).json({
        success: false,
        message: "Internal server error while fetching model analytics",
        error: error.message,
      });
    } else {
      console.error("❌ Error after response sent:", error);
    }
  }
});

 
// API to Get Task-Specific Analytics
app.get("/api/analytics/task/:task", async (req, res) => {
  try {
    const taskName = req.params.task;

    if (!taskName) {
      return res.status(400).json({ error: "Task parameter is required" });
    }

    console.log(`Fetching analytics for task: ${taskName}`);

    const response = await handleAIRequest(req, res, "analytics-task", () => `Get analytics for task: ${taskName}`);

    // Check if response is a valid string or object
    if (!response || (typeof response !== 'string' && typeof response !== 'object')) {
      console.error(`AI response is invalid for task: ${taskName}`);
      return res.status(500).json({
        error: "Invalid AI response",
        details: {
          status: "failure",
          message: "Received an invalid response from AI service",
          response: response,
        },
      });
    }

    // If the response is an object, convert it to a string (JSON)
    if (typeof response === 'object') {
      response = JSON.stringify(response, null, 2); // Pretty print if it's an object
    }

    res.json({ status: "success", task: taskName, data: response });
  } catch (error) {
    console.error(`Error in /api/analytics/task/${req.params.task}:`, error);
    res.status(500).json({ error: "Internal Server Error", details: error.message });
  }
});

const errorLogs = []; // Store error logs here

app.get("/api/analytics/errors", async (req, res) => {
  try {
    console.log("Fetching error logs...");

    if (!errorLogs.length) {
      return res.status(200).json({
        success: true,
        message: "No errors logged.",
        logs: []
      });
    }

    const aiResponse = await handleAIRequest(req, res, "fetch_errors", () => JSON.stringify(errorLogs));

    if (!aiResponse || !aiResponse.response || aiResponse.response.trim() === "") {
      console.error("❌ AI response is empty for error logs.");
      return res.status(500).json({
        success: false,
        message: "Failed to fetch error analytics",
        error: "AI response is empty"
      });
    }

    res.json({
      success: true,
      message: "Error logs fetched successfully",
      logs: JSON.parse(aiResponse.response) // Ensure it's valid JSON
    });

  } catch (error) {
    console.error("❌ Error fetching error logs:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error while fetching logs",
      error: error.message
    });
  }
});


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


const audioDir = path.join(__dirname, "generated_audio");
if (!fs.existsSync(audioDir)) {
  fs.mkdirSync(audioDir, { recursive: true });
}

app.post(
  "/api/ai/video-to-text",
  logRequest,
  validateRequest(["videoUrl"]),
  (req, res) => {
    handleAIRequest(req, res, "video-to-text", (body) => {
      const videoUrl = body.videoUrl;
      const videoPath = path.join(videosDir, path.basename(videoUrl));
      const audioPath = path.join(audioDir, path.basename(videoPath, path.extname(videoPath)) + ".wav");

      if (!fs.existsSync(videoPath)) {
        throw new Error(`❌ Video file not found: ${videoPath}`);
      }

      console.log(`🎥 Extracting audio from: ${videoPath}`);
      try {
        execSync(`ffmpeg -i "${videoPath}" -ar 16000 -ac 1 -c:a pcm_s16le "${audioPath}"`, { stdio: "inherit" });
      } catch (error) {
        throw new Error(`⚠️ Failed to extract audio: ${error.message}`);
      }

      console.log(`🔊 Audio extracted: ${audioPath}`);

      // Return transcription prompt for LLaMA
      return `Transcribe the following audio into text: ${audioPath}`;
    });
  }
);


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
const videosDir = path.join(__dirname, "generated_videos");
if (!fs.existsSync(videosDir)) {
  fs.mkdirSync(videosDir, { recursive: true });
}

// Define the generated background path
const generatedBackgroundPath = path.join(videosDir, "generated_background.mp4");

// Function to generate a dynamic background video
function generateBackgroundVideo(callback) {
  const pythonExecutable =
    process.platform === "win32"
      ? path.join(__dirname, "venv", "Scripts", "python.exe")
      : path.join(__dirname, "venv", "bin", "python");

  const backgroundScript = path.join(__dirname, "generate_background.py");

  const command = `"${pythonExecutable}" "${backgroundScript}" --output "${generatedBackgroundPath}"`;

  console.log("⏳ Generating background video...");

  try {
    execSync(command, { stdio: "inherit" });
    console.log(`✅ Background video generated at: ${generatedBackgroundPath}`);
    callback(null); // No error, proceed
  } catch (error) {
    console.warn(`⚠️ Background generation failed, but proceeding anyway.`);
    callback(null); // Proceed even if background generation fails
  }
}

app.post("/api/ai/text-to-video", async (req, res) => {
  try {
    const { text } = req.body;
    if (!text) {
      return res.status(400).json({ error: "Missing required 'text' field" });
    }

    console.log(`🎥 Generating video for: "${text}"`);

    // Define video output path
    const videoFilename = `${text.replace(/\s+/g, "_")}.mp4`;
    const videoPath = path.join(videosDir, videoFilename);

    // Ensure background is generated before proceeding
    if (!fs.existsSync(generatedBackgroundPath)) {
      generateBackgroundVideo(() => {
        processVideo(text, videoPath, res);
      });
    } else {
      processVideo(text, videoPath, res);
    }
  } catch (error) {
    console.error("❌ Error processing request:", error);
    res.status(500).json({ error: "Internal Server Error", details: error.message });
  }
});

function processVideo(text, videoPath, res) {
  const pythonExecutable =
    process.platform === "win32"
      ? path.join(__dirname, "venv", "Scripts", "python.exe")
      : path.join(__dirname, "venv", "bin", "python");

  const pythonScript = path.join(__dirname, "generate_video.py");

  // Execute Python script to generate the final video
  const command = `"${pythonExecutable}" "${pythonScript}" --text "${text}" --input "${generatedBackgroundPath}" --output "${videoPath}" --format "mp4"`;

  console.log(`🚀 Running video generation command:\n${command}`);

  exec(command, (error, stdout, stderr) => {
    console.log(`📜 Raw stdout: ${stdout.trim()}`);
    console.log(`📜 Raw stderr: ${stderr.trim()}`);

    if (error) {
      console.error(`❌ Video generation error: ${error.message}`);
      return res.status(500).json({ error: "Video generation failed", details: stderr.trim() });
    }

    if (!fs.existsSync(videoPath)) {
      console.error(`❌ Video file not found: ${videoPath}`);
      return res.status(500).json({ error: "Video file not found after generation" });
    }

    const videoUrl = `${res.req.protocol}://${res.req.get("host")}/videos/${path.basename(videoPath)}`;
    res.json({ status: "success", videoUrl });
  });
}  

// Serve videos statically
app.use("/videos", express.static(videosDir));
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

// Swagger UI setup
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Start the main server
app.listen(3000, async () => {
  try {
    console.log(`Main server is running on port 3000`);

    // Set up the AI model asynchronously and ensure it's done before processing requests
    await setupModel(4000);  // Start the AI model on port 4000

    // Wait for the AI model server to be ready before processing requests
    await waitForServer('http://localhost:4000', 5, 2000);  // 5 retries, 2 seconds delay between each

    console.log('AI model setup completed successfully!');
  } catch (error) {
    console.error('Error setting up AI model:', error);
    process.exit(1); // Exit the server if model setup fails
  }
});
