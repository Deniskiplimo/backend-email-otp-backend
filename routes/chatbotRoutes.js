const express = require('express');
const router = express.Router();

const chatbotController = require('../controllers/chatbotController');

// Route to interact with AI for both general responses and programming-related tasks
router.post('/chat', chatbotController.getAIResponse);  // Handles both programming and general chatbot requests

// Route specifically for chatbot interaction (non-programming)
router.post('/chatbot', chatbotController.getChatbotResponse);  // Handles only chatbot requests

// New route to refresh the AI model
router.post('/refresh-model', chatbotController.refreshModel);  // Triggers AI model refresh

// New route to check server health
router.get('/health', chatbotController.checkServerHealth);  // Server health check

// New route for code refactoring
router.post('/refactor-code', chatbotController.refactorCode);  // Refactor programming code

// New route for code optimization
router.post('/optimize-code', chatbotController.optimizeCode);  // Optimize programming code

// New route for generating unit tests for code
router.post('/generate', chatbotController.getAIResponse); // Generate unit tests for code
router.post('/generateunittest', chatbotController.generateUnitTestsForCode); // Generate unit tests for code

// New route for algorithm suggestion based on a problem description
router.post('/suggest-algorithm', chatbotController.suggestAlgorithm);  // Suggest algorithm for a problem

// Route for summarizing text using the AI model
router.post('/summarize', chatbotController.summarizeText);  // Summarize given text using AI model

// Route for analyzing sentiment of text using the AI model
router.post('/analyze-sentiment', chatbotController.analyzeSentiment);  // Analyze sentiment of the text using AI model

// Route for analyzing sentiment of text using the AI model
router.post('/analyze-sentiment', chatbotController.analyzeSentiment);  // Analyze sentiment of the text using AI model


module.exports = router;
