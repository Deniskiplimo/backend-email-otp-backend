// Ensure express is imported before creating app
const express = require('express');
const app = express();

const crypto = require('crypto');
const bcrypt = require('bcrypt');
const lodash = require('lodash');
const ejs = require('ejs');
const { sanitizeHtml } = require('sanitize-html');
const { createLogger, transports } = require('winston');
const queue = require('bull');
const nodemailer = require('nodemailer');
const { Otps, ResetTokens } = require('../models/otpModel');
const User = require('../models/userModel');
const { sendEmail, fallbackSendEmail } = require('../utils/sendEmail');
const logger = require('../utils/logger');
const path = require('path');

// Set EJS as the view engine
app.set('view engine', 'ejs');

// Set the views folder (optional if you're following the default structure)
app.set('views', path.join(__dirname, 'views'));

// Email Queue for async email sending
const emailQueue = new queue('emailQueue', {
  redis: {
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT,
  },
});
// Generate OTP function
function generateOTP() {
  return crypto.randomInt(100000, 999999).toString(); // Secure OTP generation
}



// Generate OTP securely
function generateOTP() {
  return crypto.randomInt(100000, 999999).toString(); 
}



// Generate a unique reset token for password reset
const generateResetToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Send OTP to the provided email address
exports.sendOTP = async (req, res) => {
  try {
    const { email } = req.query; 
    const otp = generateOTP();

    const newOTP = new Otps({ email, otp });
    await newOTP.save();

    const htmlContent = `<p>Your OTP is: <strong>${otp}</strong></p>`;
    const textContent = `Your OTP is: ${otp}`;

    // Use sendEmail utility to send the OTP
    await sendEmail({
      to: email,
      subject: 'Your OTP',
      html: htmlContent,
      text: textContent,
    });

    res.status(200).json({ success: true, message: 'OTP sent successfully' });
  } catch (error) {
    console.error('Error sending OTP:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
};

// Verify OTP sent to the user
exports.verifyOTP = async (req, res) => {
  try {
    const { email, otp } = req.query;
    const existingOTP = await Otps.findOneAndDelete({ email, otp });

    if (existingOTP) {
      res.status(200).json({ success: true, message: 'OTP verification successful' });
    } else {
      res.status(400).json({ success: false, error: 'Invalid OTP' });
    }
  } catch (error) {
    logger.error('Error verifying OTP:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
};

// Send password reset link to the email address
exports.sendResetLink = async (req, res) => {
  try {
    const { email } = req.query;

    const resetToken = generateResetToken();
    const resetTokenExpires = Date.now() + 3600000; // 1 hour expiration

    await ResetTokens.findOneAndDelete({ email }); 
    const newResetToken = new ResetTokens({
      email,
      resetToken,
      resetTokenExpires,
    });
    await newResetToken.save();

    const resetLink = `http://${process.env.HOST || 'localhost'}:${process.env.PORT || 5000}/api/reset-password/${resetToken}`;

    const htmlContent = `<p>Click <a href="${resetLink}">here</a> to reset your password.</p>`;
    const textContent = `Click the following link to reset your password: ${resetLink}`;

    // Use email queue for asynchronous email delivery
    await sendEmail({
      to: email,
      subject: 'Password Reset Link',
      html: htmlContent,
      text: textContent,
    });

    res.status(200).json({
      success: true,
      message: 'Password reset link sent successfully',
    });
  } catch (error) {
    logger.error('Error sending reset link:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
};

// Render password reset page with token
exports.renderResetPasswordPage = (req, res) => {
  res.render('password-reset', { token: req.params.token });
};

// Send feedback via email
exports.sendFeedback = async (req, res) => {
  try {
    const { email, message } = req.body;

    const htmlContent = `<p><strong>Feedback from:</strong> ${email}</p><p><strong>Message:</strong> ${message}</p>`;
    const textContent = `Feedback from: ${email}\nMessage: ${message}`;

    // Send feedback to a designated email address
    await sendEmail({
      to: 'deniskiplimo816@gmail.com', 
      subject: 'User Feedback',
      html: htmlContent,
      text: textContent,
    });

    res.status(200).json({ success: true, message: 'Feedback sent successfully' });
  } catch (error) {
    logger.error('Error sending feedback:', error);
    res.status(500).json({ success: false, error: 'Failed to send feedback' });
  }
};

// Reset password functionality
exports.resetPassword = async (req, res) => {
  try {
    const { token, newPassword, confirmPassword } = req.body;

    if (!token || !newPassword || !confirmPassword) {
      return res.status(400).json({ success: false, error: 'All fields are required' });
    }  
    
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ success: false, error: 'Passwords do not match' });
    }

    // Find the reset token in the database and check for expiration
    const resetTokenEntry = await ResetTokens.findOne({
      resetToken: token,
      resetTokenExpires: { $gt: Date.now() }, 
    });

    if (!resetTokenEntry) {
      return res.status(400).json({ success: false, error: 'Invalid or expired reset token' });
    }

    // Find the user associated with the reset token and update password
    const user = await User.findOne({ email: resetTokenEntry.email });
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    // Hash and update the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    // Delete the reset token after use
    await ResetTokens.findOneAndDelete({ resetToken: token });

    res.status(200).json({
      success: true,
      message: 'Password has been reset successfully, you can now return to the login page.',
      redirectUrl: '/api/login',
    });
  } catch (error) {
    logger.error('Error resetting password:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
};
// Email sending utility using the sendEmail utility function
// Enhanced utility to send emails with additional features
exports.sendCustomEmail = async (req, res) => {
  try {
    const {
      email,           // Recipient email address
      subject,         // Subject of the email
      html,            // HTML content of the email
      text,            // Plain text content of the email
      attachments,     // Array of attachments (optional)
      cc,              // Carbon Copy recipients (optional)
      bcc,             // Blind Carbon Copy recipients (optional)
      priority,        // Email priority ('high', 'normal', 'low')
      scheduleTime,    // Time to schedule the email (optional)
    } = req.body;

    // Validate required fields
    if (!email || !subject || (!html && !text)) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: email, subject, html/text',
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid email format',
      });
    }

    // Validate attachments (optional)
    if (attachments) {
      const allowedExtensions = ['pdf', 'docx', 'jpg', 'png'];
      const maxSize = 10 * 1024 * 1024; // 10 MB
      attachments.forEach((attachment) => {
        const ext = attachment.filename.split('.').pop().toLowerCase();
        if (!allowedExtensions.includes(ext)) {
          return res.status(400).json({
            success: false,
            error: 'Invalid attachment type. Only PDF, DOCX, JPG, PNG allowed.',
          });
        }
        if (attachment.size > maxSize) {
          return res.status(400).json({
            success: false,
            error: `Attachment size exceeds the limit of ${maxSize / 1024 / 1024} MB.`,
          });
        }
      });
    }

    // Parse emails (multiple recipients)
    const parseEmails = (emails) => emails.split(',').map(email => email.trim());
    const mailOptions = {
      to: parseEmails(email),
      cc: cc ? parseEmails(cc) : [],
      bcc: bcc ? parseEmails(bcc) : [],
      subject,
      html,
      text,
      attachments,
      priority: priority || 'normal', // Default priority is 'normal'
    };

    // Validate HTML content (basic security check)
    const isValidHtml = (htmlContent) => !/<script.*?>.*?<\/script>/gi.test(htmlContent);
    if (html && !isValidHtml(html)) {
      return res.status(400).json({
        success: false,
        error: 'HTML content contains invalid or potentially unsafe elements.',
      });
    }

    // Log the email before sending
    const logEmail = async (mailOptions, status, errorDetails = null) => {
      const logEntry = {
        email: mailOptions.to,
        subject: mailOptions.subject,
        status,
        timestamp: new Date(),
        errorDetails,
      };
      await saveLog(logEntry); // Save log to database or file
    };

    // If a schedule time is provided, handle scheduling logic
    if (scheduleTime) {
      const currentTime = new Date();
      const scheduledTime = new Date(scheduleTime);

      if (scheduledTime <= currentTime) {
        return res.status(400).json({
          success: false,
          error: 'Invalid schedule time. It must be in the future.',
        });
      }

      // Add the email to the queue for future sending
      emailQueue.add(mailOptions, { delay: scheduledTime - currentTime });
      await logEmail(mailOptions, 'scheduled');
      return res.status(200).json({ success: true, message: 'Email scheduled successfully' });
    }

    // If HTML content needs to be rendered dynamically with ejs
    if (html) {
      ejs.renderFile('templates/meetingReminder.ejs', { agendaUrl: 'https://www.phind.com/agent?cache=cm5zbdvp00002kv0cwgw4c7ct' }, (err, htmlContent) => {
        if (err) return res.status(500).json({ success: false, error: 'Error rendering email template' });
        mailOptions.html = htmlContent;

        // Send email immediately
        sendEmail(mailOptions)
          .then(() => {
            logEmail(mailOptions, 'sent');
            res.status(200).json({ success: true, message: 'Email sent successfully' });
          })
          .catch((error) => {
            logEmail(mailOptions, 'failed', error.message);
            res.status(500).json({ success: false, error: 'Failed to send email', details: error.message });
          });
      });
    } else {
      // Send email immediately if no HTML template rendering is required
      try {
        await sendEmail(mailOptions);
        await logEmail(mailOptions, 'sent');
        res.status(200).json({ success: true, message: 'Email sent successfully' });
      } catch (error) {
        await logEmail(mailOptions, 'failed', error.message);
        res.status(500).json({ success: false, error: 'Failed to send email', details: error.message });
      }
    }
  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).json({ success: false, error: 'Failed to send email', details: error.message });
  }
};