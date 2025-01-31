require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./swagger/swagger.json');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const UserAccount = require('./models/UserAccount');
const crypto = require('crypto');
const sendEmail = require('./utils/sendEmail');
const randomstring = require('randomstring');
const Otps = require('./models/otpModel');
const { execSync } = require('child_process');
const axios = require('axios');
const fs = require('fs');
const app = express();
const port = process.env.APP_PORT || 3000; // Use APP_PORT for the application server

app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
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

// Function to generate OTP
function generateOTP() {
  return randomstring.generate({
    length: 6,
    charset: 'numeric',
  });
}

// Function to send OTP via email
function sendOTP(email, otp, callback) {
  const mailOptions = {
    from: process.env.USERNAME, // Use USERNAME for the sender's email address
    to: email,
    subject: 'Your OTP Code',
    text: `Your OTP code is ${otp}`,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Error sending OTP:', error);
      callback(error);
    } else {
      console.log('OTP sent:', info.response);
      callback(null, info.response);
    }
  });
}

/**
 * @swagger
 * /api/otp/send:
 *   post:
 *     summary: Generate and send an OTP to the specified email address
 *     tags:
 *       - OTP
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: user@example.com
 *     responses:
 *       200:
 *         description: OTP sent successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: OTP sent successfully
 *       400:
 *         description: Bad request, email is required or invalid
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Email is required or invalid
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Error sending OTP
 */
app.post('/api/otp/send', async (req, res) => {
  const { email } = req.body;

  // Validate email
  if (!email || !/\S+@\S+\.\S+/.test(email)) {
    return res.status(400).json({ message: 'Email is required and must be valid' });
  }

  const otp = generateOTP();
  
  // Save OTP to the database
  const newOTP = new Otps({ email, otp });
  await newOTP.save();

  // Send OTP and handle errors
  sendOTP(email, otp, (error, response) => {
    if (error) {
      return res.status(500).json({ message: 'Error sending OTP' });
    }
    res.status(200).json({ message: 'OTP sent successfully' });
  });
});

/**
 * @swagger
 * /api/otp/verify:
 *   post:
 *     summary: Verify OTP
 *     description: Verifies the provided OTP for the given email address.
 *     tags:
 *       - OTP
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: user@example.com
 *               otp:
 *                 type: string
 *                 example: '123456'
 *     responses:
 *       200:
 *         description: OTP verification successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: OTP verification successful
 *       400:
 *         description: Invalid OTP
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Invalid OTP
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Error verifying OTP
 */
app.post('/api/otp/verify', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const existingOTP = await Otps.findOneAndDelete({ email, otp });

    if (existingOTP) {
      // OTP is valid
      res.status(200).json({ message: 'OTP verification successful' });
    } else {
      // OTP is invalid
      res.status(400).json({ message: 'Invalid OTP' });
    }
  } catch (error) {
    console.error('Error verifying OTP:', error);
    res.status(500).json({ message: 'Error verifying OTP' });
  }
});

/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Register a new user
 *     description: Creates a new user account.
 *     tags:
 *       - Authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 example: user123
 *               email:
 *                 type: string
 *                 example: user@example.com
 *               password:
 *                 type: string
 *                 example: password123
 *     responses:
 *       201:
 *         description: User registered successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: User registered successfully
 *       400:
 *         description: Bad Request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: User already exists
 */
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    let user = await UserAccount.findOne({ email });

    if (user) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    user = new UserAccount({ username, email, password: hashedPassword });

    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Login a user
 *     description: Authenticates a user and returns a JWT token.
 *     tags:
 *       - Authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 example: user@example.com
 *               password:
 *                 type: string
 *                 example: password123
 *     responses:
 *       200:
 *         description: User logged in successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   example: jwt_token_here
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Invalid credentials
 */
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await UserAccount.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: '1d',
    });

    res.status(200).json({ token });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

/**
 * @swagger
 * /api/auth/forgot-password:
 *   post:
 *     summary: Request a password reset link
 *     description: Sends an email with a password reset link containing a time-limited token.
 *     tags:
 *       - Authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 example: user@example.com
 *     responses:
 *       200:
 *         description: Password reset email sent successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 Status:
 *                   type: string
 *                   example: Success
 *                 info:
 *                   type: object
 *       404:
 *         description: User does not exist
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 Status:
 *                   type: string
 *                   example: User does not exist
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 Status:
 *                   type: string
 *                   example: Error
 *                 message:
 *                   type: string
 */
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    // Find the user by their email
    const user = await UserAccount.findOne({ email });

    if (!user) {
      return res.status(404).json({ Status: "User does not exist" });
    }

    // Generate a token for password reset
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    // Create a password reset link
    const front = process.env.FRONT_URL;
    const resetLink = `${front}/reset-password?token=${token}`;

    // Send the password reset email
    const mailOptions = {
      from: process.env.USERNAME, // Use USERNAME for the sender's email address
      to: email,
      subject: 'Password Reset Request',
      text: `You requested a password reset. Click the following link to reset your password: ${resetLink}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending email:', error);
        return res.status(500).json({ Status: "Error", message: "Failed to send email" });
      }

      res.status(200).json({ Status: "Success", info });
    });
  } catch (error) {
    res.status(500).json({ Status: "Error", message: error.message });
  }
});

/**
 * @swagger
 * /api/auth/reset-password:
 *   post:
 *     summary: Reset user password
 *     description: Resets the user's password with a valid token and new password. Ensures token validity and password strength.
 *     tags:
 *       - Authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               token:
 *                 type: string
 *                 example: jwt_reset_token_here
 *               newPassword:
 *                 type: string
 *                 example: newpassword123
 *                 minLength: 8
 *                 pattern: "^(?=.*[a-zA-Z])(?=.*[0-9]).{8,}$"
 *     responses:
 *       200:
 *         description: Password reset successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Password reset successfully
 *       400:
 *         description: Bad Request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Invalid or expired token
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: User not found
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Error resetting password
 */
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    // Validate request
    if (!token || !newPassword) {
      return res.status(400).json({ message: 'Token and new password are required' });
    }

    // Validate password strength
    if (newPassword.length < 8 || !/[0-9]/.test(newPassword) || !/[a-zA-Z]/.test(newPassword)) {
      return res.status(400).json({ message: 'Password must be at least 8 characters long and contain both letters and numbers' });
    }

    // Verify the token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    // Find the user by ID from the token
    const user = await UserAccount.findById(decoded.id);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Hash the new password and update the user's password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.status(200).json({ message: 'Password reset successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error resetting password' });
  }
});
async function downloadFile(url, outputPath) {
  if (fs.existsSync(outputPath)) {
    console.log(`${outputPath} already exists. Skipping download.`);
    return;
  }

  const writer = fs.createWriteStream(outputPath);
  const response = await axios({
    url,
    method: 'GET',
    responseType: 'stream'
  });

  const totalLength = response.headers['content-length'];

  console.log(`Starting download of ${outputPath}...`);
  let downloadedLength = 0;
  response.data.on('data', (chunk) => {
    downloadedLength += chunk.length;
    process.stdout.write(`Downloaded ${(downloadedLength / totalLength * 100).toFixed(2)}% (${downloadedLength} of ${totalLength} bytes)\r`);
  });

  response.data.pipe(writer);

  return new Promise((resolve, reject) => {
    writer.on('finish', () => {
      console.log(`\nDownload of ${outputPath} completed.`);
      resolve();
    });
    writer.on('error', reject);
  });
}

async function setupModel(port) {
  try {
    console.log('Downloading llamafile.exe...');
    await downloadFile('https://github.com/Mozilla-Ocho/llamafile/releases/download/0.6/llamafile-0.6', 'llamafile.exe');

    console.log('Downloading tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf...');
    await downloadFile('https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf', 'tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf');

    console.log('Starting llamafile.exe server...');
    execSync(`llamafile.exe -m tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf --nobrowser --port ${port}`, { stdio: 'inherit' });

  } catch (error) {
    console.error('An error occurred:', error);
  }
}

setupModel(4000);
// Swagger UI setup
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
