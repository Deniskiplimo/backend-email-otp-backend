const express = require('express');
const { sendOTP, verifyOTP, sendResetLink, resetPassword, sendFeedback, renderResetPasswordPage,sendCustomEmail } = require('../controllers/otpController');
const router = express.Router();

 
/**
 * @swagger
 * components:
 *   schemas:
 *     SendOTPRequest:
 *       type: object
 *       properties:
 *         email:
 *           type: string
 *           description: Email to send OTP to
 *       required:
 *         - email
 *     VerifyOTPRequest:
 *       type: object
 *       properties:
 *         email:
 *           type: string
 *           description: Email to verify OTP for
 *         otp:
 *           type: string
 *           description: OTP to verify
 *       required:
 *         - email
 *         - otp
 *     ResetPasswordRequest:
 *       type: object
 *       properties:
 *         token:
 *           type: string
 *           description: Reset token for password reset
 *         newPassword:
 *           type: string
 *           description: New password to set
 *         confirmPassword:
 *           type: string
 *           description: Confirmation of the new password
 *       required:
 *         - token
 *         - newPassword
 *         - confirmPassword
 *     SendEmailRequest:
 *       type: object
 *       properties:
 *         to:
 *           type: string
 *           description: Recipient email address
 *         subject:
 *           type: string
 *           description: Subject of the email
 *         html:
 *           type: string
 *           description: HTML content of the email
 *         text:
 *           type: string
 *           description: Plain text content of the email
 *       required:
 *         - to
 *         - subject
 *         - html
 *         - text
 */

/**
 * @swagger
 * /api/sendOTP:
 *   get:
 *     tags:
 *       - otp
 *     summary: Send OTP to email
 *     parameters:
 *       - in: query
 *         name: email
 *         required: true
 *         schema:
 *           type: string
 *           description: Email to send OTP to
 *     responses:
 *       200:
 *         description: OTP sent successfully
 *       500:
 *         description: Internal server error
 */
router.get('/sendOTP', sendOTP);

/**
 * @swagger
 * /api/verifyOTP:
 *   get:
 *     tags:
 *       - otp
 *     summary: Verify OTP
 *     parameters:
 *       - in: query
 *         name: email
 *         required: true
 *         schema:
 *           type: string
 *           description: Email to verify OTP for
 *       - in: query
 *         name: otp
 *         required: true
 *         schema:
 *           type: string
 *           description: OTP to verify
 *     responses:
 *       200:
 *         description: OTP verification successful
 *       400:
 *         description: Invalid OTP
 *       500:
 *         description: Internal server error
 */
router.get('/verifyOTP', verifyOTP);

/**
 * @swagger
 * /api/sendResetLink:
 *   get:
 *     tags:
 *       - otp
 *     summary: Send password reset link to email
 *     parameters:
 *       - in: query
 *         name: email
 *         required: true
 *         schema:
 *           type: string
 *           description: Email to send reset link to
 *     responses:
 *       200:
 *         description: Reset link sent successfully
 *       500:
 *         description: Internal server error
 */
router.get('/sendResetLink', sendResetLink);

/**
 * @swagger
 * /api/resetPassword:
 *   post:
 *     tags:
 *       - otp
 *     summary: Reset password using the reset token
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/ResetPasswordRequest'
 *     responses:
 *       200:
 *         description: Password has been reset successfully
 *       400:
 *         description: Invalid or expired reset token, or passwords do not match
 *       500:
 *         description: Internal server error
 */
router.post('/reset-Password', resetPassword);

/**
 * @swagger
 * /api/feedback:
 *   post:
 *     tags:
 *       - feedback
 *     summary: Send user feedback
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 description: User's email address
 *               message:
 *                 type: string
 *                 description: Feedback message
 *             required:
 *               - email
 *               - message
 *     responses:
 *       200:
 *         description: Feedback sent successfully
 *       500:
 *         description: Internal server error
 */
router.post('/feedback', sendFeedback); // Add feedback route

/**
 * @swagger
 * /api/sendEmailNotification:
 *   post:
 *     tags:
 *       - email
 *     summary: Send an email notification
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/SendEmailRequest'
 *     responses:
 *       200:
 *         description: Email sent successfully
 *       400:
 *         description: Missing required fields or invalid data
 *       500:
 *         description: Internal server error
 */
/**
 * Route to send email notification
 */
router.post('/sendEmailNotification', sendCustomEmail)
 
/**
 * Route to serve the password reset form
 */ 
router.get('/reset-Password/:token', renderResetPasswordPage);

module.exports = router;