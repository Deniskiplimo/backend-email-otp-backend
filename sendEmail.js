// sendEmail.js
const nodemailer = require('nodemailer');
const smtpTransport = require('nodemailer-smtp-transport');
require('dotenv').config();

// Create transporter object using SMTP transport
const transporter = nodemailer.createTransport(
  smtpTransport({
    host: process.env.HOST,
    port: process.env.PORTS,
    secure: false, // Use TLS if true
    auth: {
      user: process.env.USERNAME,
      pass: process.env.PASS,
    },
  })
);

// Define email options
const mailOptions = {
  from: process.env.USERNAME,
  to: 'deniskiplimo816@gmail.com',
  subject: 'Test Email',
  text: 'This is a test email.',
};

// Send email
transporter.sendMail(mailOptions, (error, info) => {
  if (error) {
    return console.log('Error:', error);
  }
  console.log('Email sent:', info.response);
});
