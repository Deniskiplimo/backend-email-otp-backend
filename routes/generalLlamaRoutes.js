const express = require("express");
const {
    handleChatRequest,
    handleSummarizeRequest,
    handleRefactorCodeRequest,
    handleUnitTestRequest,
    handleUtteranceRequest
} = require("../controllers/generalLlamaController");

const router = express.Router();

// Route for chatbot interaction
router.post("/chat", handleChatRequest);

// Route for text summarization
router.post("/summarize", handleSummarizeRequest);

// Route for refactoring code
router.post("/refactor", handleRefactorCodeRequest);

// Route for unit test generation
router.post("/unittest", handleUnitTestRequest);

// Route for handling utterances
router.post("/utterance", handleUtteranceRequest);

module.exports = router;
