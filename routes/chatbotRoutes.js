const express = require('express');
const router = express.Router();

const chatbotController = require('../controllers/chatbotController');

// Route to interact with AI for both general responses and programming-related tasks
router.post('/chat', chatbotController.getAIResponse);  // General AI response

// Route specifically for chatbot interaction (non-programming)
router.post('/chatbot', chatbotController.getChatbotResponse);

module.exports = router;
