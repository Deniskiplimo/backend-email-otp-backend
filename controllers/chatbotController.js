// Importing necessary modules
const { llamacpp, streamText } = require("modelfusion");
const { codeLlama: importedCodeLlama } = require('../codeLlama'); // Renaming to avoid conflict
const { generalLlama } = require('../generalLlama'); // Correctly importing generalLlama as a function
const refreshModel = require('../models/refreshTokenModel');
// Helper function for logging (can be extended for more sophisticated logging)
const logRequest = (message, data) => {
    console.log(`[Request Log] ${message}:`, data);
};

// Function to validate port input
const isValidPort = (port) => {
    return !isNaN(port) && port > 0 && port <= 65535;
};

// Function to handle AI responses for generic and programming-related tasks
exports.getAIResponse = async (req, res) => {
    const { prompt, language, port } = req.body;

    // Validate inputs
    if (!prompt) {
        return res.status(400).json({ error: 'Prompt is required' });
    }

    if (!port || !isValidPort(port)) {
        return res.status(400).json({ error: 'Invalid or missing port' });
    }

    logRequest('Received request', req.body); // Log the entire request for debugging

    try {
        // Handle programming-related requests (CodeLlama)
        if (isProgrammingTask(prompt)) {
            if (!language) {
                return res.status(400).json({ error: 'Language is required for programming tasks' });
            }

            logRequest('Programming request detected', prompt);

            // Call CodeLlama for programming-related instructions
            const response = await importedCodeLlama(prompt, language, port); 
            return res.status(200).json({ response });

        } else {
            // Handle general chatbot responses (non-programming related)
            logRequest('General chatbot request detected', prompt);

            // Call the chatbot service
            const response = await getChatbotResponse(prompt, port); 
            return res.status(200).json({ response });
        }
    } catch (error) {
        console.error('AI Response error:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
};

// Function to check if the task is programming-related
const isProgrammingTask = (prompt) => {
    return prompt.toLowerCase().includes('create') || prompt.toLowerCase().includes('generate');
};

async function getChatbotResponse(prompt, port) {
    try {
        console.log("Received prompt:", prompt);
        logRequest('Generating chatbot response', prompt);

        // Simulate chatbot response (you can replace this with actual AI logic)
        const simulatedResponse = `Chatbot response to: ${prompt}`;
        console.log("Chatbot response generated:", simulatedResponse);

        // Ensure that response is returned
        return simulatedResponse;

    } catch (error) {
        console.error('Error generating chatbot response:', error);
        throw new Error('Error generating chatbot response');
    }
}

// Function for refreshing the model to optimize responses (if applicable)
exports.refreshModel = async () => {
    try {
        console.log('Refreshing AI models...');
        // Placeholder for model refresh logic if necessary
        return 'Models refreshed successfully';
    } catch (error) {
        console.error('Error refreshing models:', error);
        throw new Error('Error refreshing AI models');
    }
};

// Function to check if the server is live and responding
exports.checkServerHealth = (req, res) => {
    try {
        // Simple health check
        return res.status(200).json({ status: 'Server is up and running' });
    } catch (error) {
        console.error('Error checking server health:', error);
        return res.status(500).json({ error: 'Error checking server health' });
    }
};

// Exporting the individual functions for easier testing or usage elsewhere
exports.getChatbotResponse = getChatbotResponse;
