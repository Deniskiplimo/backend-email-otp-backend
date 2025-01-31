const nodemailer = require('nodemailer');
const handlebars = require('handlebars');
const fs = require('fs');
const path = require('path');

// Function for the fallback email sending
const fallbackSendEmail = async (options) => {
  // Use an alternative email service or method (e.g., send via a different SMTP provider or API)
  try {
    console.log("Attempting to send email using fallback method...");
    // Example fallback transport, for instance using a different SMTP server or API.
    const fallbackTransporter = nodemailer.createTransport({
      service: 'Gmail',  // Using Gmail SMTP as fallback (or another provider)
      auth: {
        user: process.env.FALLBACK_EMAIL,  // Fallback email user (e.g., Gmail account)
        pass: process.env.FALLBACK_EMAIL_PASSWORD, // Fallback email password
      },
    });

    // Send email using the fallback transporter
    const fallbackMailOptions = {
      from: process.env.FALLBACK_EMAIL,
      to: options.to,
      subject: options.subject,
      html: options.html,
      text: options.text,
    };

    await fallbackTransporter.sendMail(fallbackMailOptions);
    console.log('Fallback email sent successfully:', options.to);
  } catch (error) {
    console.error('Fallback email failed:', error);
    throw new Error('Both primary and fallback email methods failed');
  }
};

// Function for sending email with the primary SMTP method
const sendEmail = async (options) => {
  // Validate environment variables for MailerSend SMTP configuration
  const { SMTP_HOST, SMTP_PORT, SMTP_MAIL, SMTP_APP_PASS } = process.env;
  if (!SMTP_HOST || !SMTP_MAIL || !SMTP_APP_PASS) {
    throw new Error('Missing required SMTP environment variables.');
  }

  // Validate required options
  if (!options.to) throw new Error('Recipient email address (to) is required.');
  if (!options.subject) throw new Error('Email subject is required.');

  // Create transporter using Nodemailer and MailerSend SMTP credentials
  const transporter = nodemailer.createTransport({
    host: SMTP_HOST,                   // MailerSend SMTP host
    port: parseInt(SMTP_PORT, 10),     // Port (usually 587 for STARTTLS)
    secure: SMTP_PORT == 465,          // SSL/TLS for port 465
    auth: {
      user: SMTP_MAIL,                 // MailerSend email address
      pass: SMTP_APP_PASS,             // MailerSend SMTP app password
    },
    tls: {
      rejectUnauthorized: false,       // Allow self-signed certificates
    },
  });

  let html = options.html || '';        // Default to provided HTML content
  let text = options.text || '';        // Default to provided plain text content

  // Compile template if templatePath and context are provided
  if (options.templatePath && options.context) {
    try {
      const templateSource = fs.readFileSync(path.join(__dirname, options.templatePath), 'utf8');
      const template = handlebars.compile(templateSource);
      html = template(options.context);         // Generate HTML content using Handlebars
      text = html.replace(/<[^>]*>/g, '');      // Generate plain text from HTML
    } catch (err) {
      console.error('Error reading or compiling template:', err);
      throw new Error('Template compilation error');
    }
  }

  // Ensure that at least one of HTML or text content is present
  if (!html && !text) {
    throw new Error('Both HTML and text content cannot be empty.');
  }

  // Define the mail options
  const mailOptions = {
    from: SMTP_MAIL,       // Sender's email address
    to: options.to,        // Recipient's email address
    subject: options.subject,
    html: html,             // HTML content (if provided)
    text: text,             // Plain text content (if provided)
  };

  // Send the email
  try {
    await transporter.sendMail(mailOptions);
    console.log('Email sent successfully:', options.to);
  } catch (error) {
    console.error('Error sending email with primary method:', error);
    // Attempt to send using fallback method if primary fails
    await fallbackSendEmail(options);
  }
};

module.exports = { sendEmail, fallbackSendEmail };