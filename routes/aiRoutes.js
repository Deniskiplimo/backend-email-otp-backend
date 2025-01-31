const express = require('express');
const router = express.Router();
const chatbotController = require('../controllers/chatbotController');

// Chatbot-specific route
router.post('/', chatbotController.getChatbotResponse);
