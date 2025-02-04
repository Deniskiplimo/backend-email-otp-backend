// Import the necessary function from generalLlama
const { generalLlama } = require("../generalLlama");
const { llamacpp, streamText } = require("modelfusion");
// Handle chatbot interaction
async function handleChatRequest(req, res) {
    const { message, userId } = req.body;  // Assuming userId for context-based chat
    const LLAMA_PORT = process.env.LLAMA_PORT || 4000;  // Default to 4000 if not provided

    if (!message || !userId) {
        return res.status(400).json({ error: "Message and userId are required." });
    }

    try {
        const chatResponse = await generalLlama(`Chat with user ${userId}: ${message}`, LLAMA_PORT);
        res.json({ result: chatResponse });
    } catch (error) {
        res.status(500).json({ error: "Failed to process the chat request." });
    }
}

// Handle text summarization
async function handleSummarizeRequest(req, res) {
    const { text } = req.body;
    const LLAMA_PORT = process.env.LLAMA_PORT || 4000;

    if (!text) {
        return res.status(400).json({ error: "Text is required." });
    }

    try {
        const summary = await generalLlama(`Summarize the following text: ${text}`, LLAMA_PORT);
        res.json({ result: summary });
    } catch (error) {
        res.status(500).json({ error: "Failed to summarize the text." });
    }
}

// Handle code refactoring
async function handleRefactorCodeRequest(req, res) {
    const { code } = req.body;
    const LLAMA_PORT = process.env.LLAMA_PORT || 4000;

    if (!code) {
        return res.status(400).json({ error: "Code is required." });
    }

    try {
        const refactoredCode = await generalLlama(`Refactor the following code for better readability: ${code}`, LLAMA_PORT);
        res.json({ result: refactoredCode });
    } catch (error) {
        res.status(500).json({ error: "Failed to refactor the code." });
    }
}

// Handle unit test generation
async function handleUnitTestRequest(req, res) {
    const { code, testCase } = req.body;
    const LLAMA_PORT = process.env.LLAMA_PORT || 4000;

    if (!code || !testCase) {
        return res.status(400).json({ error: "Code and testCase are required." });
    }

    try {
        const unitTestCode = await generalLlama(`Write unit tests for the following code: ${code} with test case: ${testCase}`, LLAMA_PORT);
        res.json({ result: unitTestCode });
    } catch (error) {
        res.status(500).json({ error: "Failed to generate unit tests." });
    }
}

// Handle natural language utterances
async function handleUtteranceRequest(req, res) {
    const { utterance } = req.body;
    const LLAMA_PORT = process.env.LLAMA_PORT || 4000;

    if (!utterance) {
        return res.status(400).json({ error: "Utterance is required." });
    }

    try {
        const response = await generalLlama(`Respond to this utterance: ${utterance}`, LLAMA_PORT);
        res.json({ result: response });
    } catch (error) {
        res.status(500).json({ error: "Failed to respond to the utterance." });
    }
}

// Exporting all the controller functions
module.exports = {
    handleChatRequest,
    handleSummarizeRequest,
    handleRefactorCodeRequest,
    handleUnitTestRequest,
    handleUtteranceRequest
};
