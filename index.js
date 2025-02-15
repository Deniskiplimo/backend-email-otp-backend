require('dotenv').config();
const { generateCode, summarizeText, translateText } = require('./generalLlama');
const moment = require("moment");
const { generateCodeWithCodeLlama } = require('./codeLlama');
const path = require('path');
const { llamacpp, streamText } = require("modelfusion");
const ip = '8.8.8.8';
const os = require('os');
const PORT = 4000;
const { parentPort, workerData, isMainThread } = require("worker_threads");
const { query, validationResult } = require('express-validator');
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
      console.log(`\nDownload of ${outputPath} completed.`);
      fs.chmodSync(outputPath, 0o755); // Add execute permissions
      resolve();
    });
    writer.on("error", reject);
  });
}

// ✅ Function to start the AI server
async function setupModel(port) {
  try {
    await downloadFile(
      "https://github.com/Mozilla-Ocho/llamafile/releases/download/0.6/llamafile-0.6",
      "llamafile.exe"
    );
    await downloadFile(
      "https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
      "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
    );

    console.log(`Starting AI server on port ${port}...`);
    const command = `./llamafile.exe -m tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf --nobrowser --port ${port}`;
    exec(command, (error, stdout, stderr) => {
      if (error) return console.error(`Error: ${error.message}`);
      if (stderr) return console.error(`stderr: ${stderr}`);
      console.log(stdout);
    });
  } catch (error) {
    console.error("Setup error:", error);
    throw error;
  }
}

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

const nThreadsDefault = Math.max(1, os.cpus().length - 1);

async function executeLlama(options = {}) {
  const {
    prompt,
    model = "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
    task = "default",
    socket = null,
    maxTokens = 256,
    temperature = 0.7,
    topK = 50,
    
    nThreads = Math.max(2, os.cpus().length - 1), // Optimize thread allocation
  } = options;

  if (!prompt || typeof prompt !== "string" || prompt.trim() === "") {
    console.error("❌ Invalid prompt received:", prompt);
    return Promise.reject({ message: "❌ Invalid prompt", details: "Prompt must be a non-empty string." });
  }

  console.log(`📝 Running Llama with prompt: "${prompt}" using ${nThreads} threads`);

  return runLlamaModel({ prompt, model, socket, maxTokens, temperature, topK, nThreads });
}


async function runLlamaModel({ prompt, model, socket, maxTokens, temperature, topK, nThreads, port = PORT }) { 
  return new Promise(async (resolve, reject) => {
      console.log("📝 Running Llama with:", { port, prompt, maxTokens, temperature, topK, nThreads });

      if (!port) {
          return reject({ message: "❌ Port is missing!" });
      }

      const isServerReady = await checkServerAvailability(port);
      if (!isServerReady) {
          return reject({ message: "❌ Llama server is not available" });
      }

      const llamaSystemPrompt =
          `You are an AI assistant here to help with programming tasks. ` +
          `Your responses will be clear, concise, and code-oriented. ` +
          `Please follow the instructions and generate the requested code.`;

      const api = llamacpp.Api({
          baseUrl: `http://localhost:${port}`, // ✅ Fixed port usage
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
app.post("/api/ai/start", async (req, res) => {
  try {
    await setupModel(AI_PORT);
    await waitForServer(`http://localhost:${AI_PORT}`);
    res.json({ message: "AI Server started successfully", port: AI_PORT });
  } catch (error) {
    res.status(500).json({ error: "AI Server failed to start", details: error.message });
  }
});

// ✅ AI Execution API
app.post("/api/ai/execute", logRequest, async (req, res) => {
  try {
    const { prompt, task, maxTokens, temperature, topK } = req.body;

    // Validate input
    if (!prompt) {
      return res.status(400).json({ error: "Prompt is required" });
    }

    console.log("Received request:", { prompt, task, maxTokens, temperature, topK });

    // Call AI execution function
    const response = await executeLlama({ prompt, task, maxTokens, temperature, topK });

    // Debug response
    console.log("AI Response:", response);

    // Ensure response is valid
    if (!response || Object.keys(response).length === 0) {
      return res.status(500).json({ error: "AI execution returned an empty response" });
    }

    res.json({
      status: "success",
      message: "Response generated successfully",
      response: response,
    });
  } catch (error) {
    console.error("Execution failed:", error);
    res.status(500).json({ error: "Execution failed", details: error.message });
  }
}); 


app.post("/api/ai/summarize", logRequest, async (req, res) => {
  try {
    const { text, maxTokens, temperature } = req.body;
    if (!text) {
      return res.status(400).json({ error: "Text is required" });
    }

    const response = await executeLlama({ prompt: `Summarize: ${text}`, task: "summarization", maxTokens, temperature });
    res.json(response);
  } catch (error) {
    res.status(500).json({ error: "Summarization failed", details: error.message });
  }
});

app.post("/api/ai/generate-blog", logRequest, async (req, res) => {
  try {
    const { topic, wordCount, tone, temperature } = req.body;
    if (!topic) {
      return res.status(400).json({ error: "Topic is required" });
    }

    const response = await executeLlama({ prompt: `Write a ${tone} blog post on: ${topic}`, task: "text-generation", maxTokens: wordCount, temperature });
    res.json(response);
  } catch (error) {
    res.status(500).json({ error: "Blog generation failed", details: error.message });
  }
});

app.post("/api/ai/translate", logRequest, async (req, res) => {
  try {
    const { text, sourceLang, targetLang } = req.body;
    if (!text || !sourceLang || !targetLang) {
      return res.status(400).json({ error: "Text, sourceLang, and targetLang are required" });
    }

    const response = await executeLlama({ prompt: `Translate '${text}' from ${sourceLang} to ${targetLang}:`, task: "translation" });
    res.json(response);
  } catch (error) {
    res.status(500).json({ error: "Translation failed", details: error.message });
  }
});
app.post("/api/ai/generate-code", logRequest, async (req, res) => {
  try {
    const { description, language, maxTokens = 100, temperature = 0.7 } = req.body;

    if (!description || !language) {
      return res.status(400).json({ error: "Description and language are required" });
    }

    console.log(`📝 Generating ${language} code for: "${description}"`);

    const result = await executeLlama({ 
      prompt: `Write a ${language} function to ${description}. Provide well-structured, optimized, and documented code.`,
      task: "code-generation", 
      maxTokens, 
      temperature 
    });

    if (!result || typeof result.response !== "string") {
      return res.status(500).json({ error: "Invalid response from AI model" });
    }

    res.json({ 
      status: "success",
      message: "Code generated successfully",
      language,
      code: result.response.trim() 
    });

  } catch (error) {
    console.error("❌ Code generation failed:", error.message);
    res.status(500).json({ error: "Code generation failed", details: error.message });
  }
});


 
app.post("/api/ai/chat", logRequest, async (req, res) => {
  try {
    const { message, context, temperature } = req.body;
    if (!message) {
      return res.status(400).json({ error: "Message is required" });
    }

    const response = await executeLlama({ prompt: `Chatbot response to: '${message}' in context '${context}'`, task: "chat", temperature });
    res.json(response);
  } catch (error) {
    res.status(500).json({ error: "Chat response failed", details: error.message });
  }
});

app.post("/api/ai/generate-sql", logRequest, async (req, res) => {
  try {
    const { description, databaseType, temperature } = req.body;
    if (!description || !databaseType) {
      return res.status(400).json({ error: "Description and databaseType are required" });
    }

    const response = await executeLlama({ prompt: `Generate a ${databaseType} SQL query for: ${description}`, task: "sql-generation", temperature });
    res.json(response);
  } catch (error) {
    res.status(500).json({ error: "SQL generation failed", details: error.message });
  }
});


app.post("/api/ai/sentiment", logRequest, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text) {
      return res.status(400).json({ error: "Text is required" });
    }

    res.setHeader("Content-Type", "application/json");

    const result = await executeLlama({ 
      prompt: `Analyze sentiment: "${text}"`, 
      task: "sentiment-analysis", 
      maxTokens: 50 
    });

    if (!result || typeof result.response !== "string") {
      return res.status(500).json({ error: "Invalid response from AI model" });
    }

    res.json({ sentiment: result.response });

  } catch (error) {
    console.error("❌ Sentiment analysis failed:", error.message);
    res.status(500).json({ error: "Sentiment analysis failed", details: error.message });
  }
});




// ✅ AI Data Analysis
app.post("/api/ai/analyze-data", logRequest, async (req, res) => {
  try {
    const { dataset, question } = req.body;
    if (!dataset || !question) {
      return res.status(400).json({ error: "Dataset and question are required" });
    }

    const response = await executeLlama({ prompt: `Analyze this dataset and answer: ${question}\n${JSON.stringify(dataset)}`, task: "data-analysis" });
    res.json(response);
  } catch (error) {
    res.status(500).json({ error: "Data analysis failed", details: error.message });
  }
});

// ✅ AI Grammar Check
app.post("/api/ai/grammar-check", logRequest, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text) {
      return res.status(400).json({ error: "Text is required" });
    }

    const response = await executeLlama({ prompt: `Correct the grammar in: ${text}`, task: "grammar-correction" });
    res.json(response);
  } catch (error) {
    res.status(500).json({ error: "Grammar correction failed", details: error.message });
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
