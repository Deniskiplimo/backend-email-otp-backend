const { codeLlama: importedCodeLlama } = require('../codeLlama');
const { generalLlama } = require('../generalLlama');
const { llamacpp, streamText } = require("modelfusion");
const axios = require('axios');

/**
 * Validate if the given port number is within the valid range.
 */
function isValidPort(port) {
    const portNumber = parseInt(port, 10);
    return portNumber >= 1 && portNumber <= 65535;
}

/**
 * Logs incoming requests with method and URL.
 */
function logRequest(req, additionalData = {}) {
    console.log(`[${new Date().toISOString()}] Request received`);
    console.log(`Method: ${req.method}, URL: ${req.originalUrl}`);
    if (Object.keys(additionalData).length > 0) {
        console.log("Additional Data:", additionalData);
    }
}

/**
 * Determines if the given task is related to programming.
 */
function isProgrammingTask(task) {
    const programmingKeywords = ['code', 'programming', 'development', 'script', 'algorithm'];
    return programmingKeywords.some(keyword => task.toLowerCase().includes(keyword));
}

// Default AI model server port (fallback to environment variable if available)
const DEFAULT_PORT = process.env.AI_SERVER_PORT || 4000;

/**
 * Get the running AI server port.
 */
function getRunningPort() {
    return process.env.AI_SERVER_PORT || DEFAULT_PORT;
}

/**
 * Fetch AI response from the local AI server.
 */
async function fetchAIResponseFromServer(instruction, language, port = getRunningPort()) {
    const url = `http://127.0.0.1:${port}/`;  

    try {
        const response = await axios.post(url, { prompt: instruction, language, port });
        return response.data.response;
    } catch (error) {
        console.error('❌ Error fetching response from AI server:', error.message);
        return "Error occurred while contacting AI model server.";
    }
}

/**
 * Main API handler to process AI requests.
 */
exports.getAIResponse = async (req, res) => {
    let { prompt, instruction, language, port } = req.body;

    prompt = prompt || instruction;
    port = Number(port) || getRunningPort();  

    if (!prompt || typeof prompt !== "string" || prompt.trim() === "") {
        return res.status(400).json({ error: 'Prompt is required and must be a non-empty string' });
    }

    if (!isValidPort(port)) {
        return res.status(400).json({ error: 'Invalid port number' });
    }

    logRequest(req, { prompt, language, port });

    try {
        let response;

        if (isProgrammingTask(prompt)) {
            language = language || "python";  
            console.log(`Detected programming request, using CodeLlama for ${language}.`);
            response = await importedCodeLlama(prompt, language, port);
        } else {
            console.log("Detected general chatbot request, using GeneralLlama.");
            response = await generalLlama(prompt, port);
        }

        if (!response) {
            throw new Error('Empty response received from AI model');
        }

        return res.status(200).json({ response });

    } catch (error) {
        console.error('❌ AI Response Error:', error);
        return res.status(500).json({ error: 'Internal server error', details: error.message });
    }
};

/**
 * Handles AI-generated code responses using CodeLlama.
 */
async function codeLlama(instruction, language, port) {
    const llamaSystemPrompt = `You are an AI assistant for programming tasks. Generate code in the specified language.`;

    const api = llamacpp.Api({ baseUrl: `http://localhost:${port}` });

    console.log(`🔄 Sending request to model server (Port: ${port})...`);
    console.log(`Instruction: ${instruction} | Language: ${language}`);

    try {
        const timeout = 5000;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        const textStream = await streamText({
            signal: controller.signal,
            model: llamacpp
                .CompletionTextGenerator({ api, temperature: 0, stopSequences: ["\n```"] })
                .withInstructionPrompt(),
            prompt: {
                system: llamaSystemPrompt,
                instruction,
                responsePrefix: `Here is the program in ${language}:\n\`\`\`${language}\n`,
            },
        });

        let response = "";
        for await (const textPart of textStream) {
            process.stdout.write(textPart);
            response += textPart;
        }

        clearTimeout(timeoutId);
        console.log("\n✅ Response completed.");
        return response;

    } catch (error) {
        console.error("❌ Error generating code:", error.message);
        return "An error occurred while generating the response.";
    }
}


/**
 * Summarizes text using the AI model.
 * @param {string} text - The text to summarize.
 * @param {number} port - The AI server port.
 * @returns {Promise<string>} - AI-generated summary.
 */
exports.summarizeText = async (text, port) => {
    exports.log("INFO", `📜 Summarizing text (Length: ${text.length} chars)`);
    return await exports.fetchAIResponseFromServer(`Summarize: ${text}`, "English", port);
};

/**
 * Analyzes text sentiment using the AI model.
 * @param {string} text - The text to analyze.
 * @param {number} port - The AI server port.
 * @returns {Promise<string>} - Sentiment analysis result.
 */
exports.analyzeSentiment = async (text, port) => {
    exports.log("INFO", `🧐 Analyzing sentiment of text`);
    return await exports.fetchAIResponseFromServer(`Analyze sentiment: ${text}`, "English", port);
};

/**
 * Provides chatbot functionality by interacting with AI.
 * @param {string} userMessage - The user's message.
 * @param {number} port - The AI server port.
 * @returns {Promise<string>} - AI-generated chatbot response.
 */
exports.chatbot = async (userMessage, port) => {
    exports.log("INFO", `💬 Chatbot processing message: "${userMessage}"`);
    return await exports.fetchAIResponseFromServer(userMessage, "English", port);
};

/**
 * Refactors code for better readability and performance.
 * @param {string} code - The source code to refactor.
 * @param {string} language - Programming language.
 * @param {number} port - The AI server port.
 * @returns {Promise<string>} - Refactored code.
 */
exports.refactorCode = async (code, language, port = 4000) => {
    exports.log("INFO", `🔄 Refactoring ${language} code...`);

    const llamaSystemPrompt = `You are an AI assistant specializing in code refactoring. Improve the given code while maintaining its functionality.`;

    const validPort = Number.isNaN(Number(port)) ? 4000 : port;
    const api = new llamacpp.Api({
        baseUrl: `http://localhost:${validPort}`,
    });

    const timeout = 10000; // Increased timeout to 10 seconds
    const controller = new AbortController();
    let timeoutId;

    try {
        timeoutId = setTimeout(() => {
            controller.abort();
            exports.log("ERROR", "⏳ Request timed out.");
        }, timeout);

        // Ensure 'code' is a valid string
        if (typeof code !== 'string') {
            if (typeof code === 'object' && code !== null) {
                if (code.body?.code) {
                    // Extract `code` from request body if present
                    code = code.body.code;
                } else {
                    exports.log("ERROR", "❌ Invalid 'code' parameter. Expected a string or valid object.");
                    return "Error: Invalid code input.";
                }
            } else {
                exports.log("ERROR", "❌ Code must be a string.");
                return "Error: Code must be a string.";
            }
        }

        // Log sanitized input
        exports.log("INFO", `Sending code to AI server:\n${code}`);
        exports.log("INFO", `Language: ${language}`);

        // Stream AI-generated refactored code
        const textStream = await streamText({
            signal: controller.signal,
            model: new llamacpp.CompletionTextGenerator({
                api,
                temperature: 0,
                stopSequences: ["\n"],
            }),
            prompt: {
                system: llamaSystemPrompt,
                instruction: `Please refactor the following ${language} code for better readability and efficiency:\n\`\`\`${language}\n${code}\n\`\`\``,
                responsePrefix: "Refactored code:\n",
            },
        });

        let response = "";
        for await (const textPart of textStream) {
            response += textPart;
        }

        clearTimeout(timeoutId); // Clear timeout after success
        exports.log("INFO", "✅ Response completed.");
        return response.trim() || "No refactored code returned.";

    } catch (error) {
        clearTimeout(timeoutId); // Clear timeout in case of error
        
        // Log detailed error
        exports.log("ERROR", `❌ Refactoring error: ${error.message}`);

        if (error.response) {
            exports.log("ERROR", `API response: ${JSON.stringify(error.response)}`);
        } else if (error.stack) {
            exports.log("ERROR", `Stack trace: ${error.stack}`);
        }

        return `An error occurred while refactoring the code: ${error.message}`;
    }
};

/**
 * Optimizes code for better performance.
 * @param {string} code - The source code to optimize.
 * @param {string} language - Programming language.
 * @param {number} port - The AI server port.
 * @returns {Promise<string>} - Optimized code.
 */
exports.optimizeCode = async (code, language, port = 4000) => {
    exports.log("INFO", `🚀 Optimizing ${language} code...`);

    if (!port || isNaN(port)) {
        exports.log("ERROR", `❌ Invalid port: ${port}. Using default port 4000.`);
        port = 4000; // Default port if invalid
    }

    const llamaSystemPrompt = `You are an AI assistant specializing in code optimization. Improve the given code by reducing time complexity or memory usage.`;

    const api = new llamacpp.Api({
        baseUrl: `http://localhost:${port}`,
    });

    let timeoutId = null; // Declare timeoutId outside try block

    try {
        const timeout = 5000;
        const controller = new AbortController();
        timeoutId = setTimeout(() => controller.abort(), timeout); // Assign timeoutId

        const textStream = await streamText({
            signal: controller.signal,
            model: new llamacpp.CompletionTextGenerator({
                api,
                temperature: 0,
                stopSequences: ["\n"],
            }),
            prompt: {
                system: llamaSystemPrompt,
                instruction: `Optimize the following ${language} code for performance:\n\`\`\`${language}\n${code}\n\`\`\``,
                responsePrefix: "Optimized code:\n",
            },
        });

        let response = "";
        for await (const textPart of textStream) {
            response += textPart;
        }

        clearTimeout(timeoutId);
        return response.trim() || "No optimized code returned.";

    } catch (error) {
        if (timeoutId) clearTimeout(timeoutId); // Only clear timeout if it was set
        exports.log("ERROR", `❌ Optimization error: ${error.message}`);
        return "An error occurred while optimizing the code.";
    }
};

/**
 * Main API handler to process AI requests.
 * @param {Object} req - Express request object.
 * @param {Object} res - Express response object.
 */
exports.getAIResponse = async (req, res) => {
    let { prompt, instruction, language, port } = req.body;

    prompt = prompt || instruction;
    port = Number(port) || getRunningPort();

    if (!prompt || typeof prompt !== "string" || !prompt.trim()) {
        return res.status(400).json({ error: 'Prompt is required and must be a non-empty string' });
    }

    if (!isValidPort(port)) {
        return res.status(400).json({ error: 'Invalid port number' });
    }

    exports.log("INFO", `Request received with prompt: "${prompt}"`);

    try {
        let response;
        if (isProgrammingTask(prompt)) {
            language = language || "python";
            exports.log("INFO", `🖥️ Detected programming request. Using CodeLlama for ${language}.`);
            response = await importedCodeLlama(prompt, language, port);
        } else {
            exports.log("INFO", "💬 General chatbot request detected. Using GeneralLlama.");
            response = await generalLlama(prompt, port);
        }

        if (!response) {
            throw new Error('Empty response received from AI model');
        }

        return res.status(200).json({ response });
    } catch (error) {
        exports.log("ERROR", `🚨 AI Response Error: ${error.message}`);
        return res.status(500).json({ error: 'Internal server error', details: error.message });
    }
};

/**
 * Helper function for logging.
 * @param {string} level - Log level (INFO, ERROR, etc.).
 * @param {string} message - Log message.
 */
exports.log = (level, message) => {
    console.log(`[${level}] ${message}`);
};

/**
 * Suggests an algorithm for a given problem.
 * @param {string} problemDescription - Description of the problem.
 * @param {number} port - The AI server port.
 * @returns {Promise<string>} - Suggested algorithm.
 */
exports.suggestAlgorithm = async (problemDescription, port = 4000) => {
    const llamaSystemPrompt = `You are an AI assistant specializing in algorithm design. 
    Given a problem description, suggest an appropriate algorithm or approach to solve it.`;

    const api = new llamacpp.Api({
        baseUrl: `http://localhost:${port}`,
    });

    let timeoutId = null;

    try {
        const timeout = 5000;
        const controller = new AbortController();
        timeoutId = setTimeout(() => {
            exports.log("ERROR", "❌ Timeout: Request took too long, aborting...");
            controller.abort();
        }, timeout);

        exports.log("INFO", "✅ Requesting algorithm suggestion...");

        const textStream = await streamText({
            signal: controller.signal,
            model: new llamacpp.CompletionTextGenerator({
                api,
                temperature: 0,
                stopSequences: ["\n"],
            }),
            prompt: {
                system: llamaSystemPrompt,
                instruction: `Suggest an algorithm or approach to solve the following problem:\n${problemDescription}`,
                responsePrefix: "Suggested Algorithm:\n",
            },
        });

        let response = "";
        for await (const textPart of textStream) {
            if (!textPart) break;
            exports.log("INFO", `📝 Received: ${textPart}`);
            response += textPart;
        }

        clearTimeout(timeoutId);
        exports.log("INFO", "✅ Response complete.");
        return response.trim() || "No response received.";

    } catch (error) {
        exports.log("ERROR", `❌ Error suggesting algorithm: ${error.message}`);
        if (timeoutId) clearTimeout(timeoutId);
        return "An error occurred while suggesting an algorithm.";
    }
};

// Express route handler to process API requests for algorithm suggestions
exports.generateAlgorithmSuggestion = async (req, res) => {
    const { problemDescription, port } = req.body;

    if (!problemDescription) {
        return res.status(400).json({ error: "Problem description is required." });
    }

    try {
        const response = await exports.suggestAlgorithm(problemDescription, port);
        return res.json({ algorithm: response });
    } catch (error) {
        exports.log("ERROR", `❌ Error generating algorithm suggestion: ${error.message}`);
        return res.status(500).json({ error: "An error occurred while generating the algorithm suggestion." });
    }
};

// Function to check if AI server is available
exports.checkServerAvailability = async (port) => {
    const serverUrl = `http://localhost:${port}`;
    try {
        await axios.get(serverUrl);
        exports.log("INFO", `✅ AI server is ready at ${serverUrl}`);
        return true;
    } catch (error) {
        exports.log("ERROR", `❌ Server is unavailable at ${serverUrl}`);
        return false;
    }
};

/**
 * Generates a chatbot response using the AI model.
 * @param {string} prompt - The user's input.
 * @param {number} port - The AI server port (default: 4000).
 * @returns {Promise<string>} - AI-generated chatbot response.
 */
exports.getChatbotResponse = async function (prompt, port = 4000) {
    const timeout = 5000;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
        console.log("INFO: Generating chatbot response...");

        const isServerReady = await exports.checkServerAvailability(port);
        if (!isServerReady) {
            return "Server is unavailable. Please try again later.";
        }

        const serverUrl = `http://localhost:${port}`;
        const api = new llamacpp.Api({ serverUrl });

        const textStream = await streamText({
            signal: controller.signal,
            model: new llamacpp.CompletionTextGenerator({
                api,
                temperature: 0.7, // Slight randomness for more natural responses
                stopSequences: ["\n"], // Ensures cleaner responses
            }).withInstructionPrompt(),
            prompt: {
                system: "You are an AI chatbot that provides helpful and concise responses.",
                instruction: prompt,
                responsePrefix: "AI:",
            },
        });

        let response = "";
        for await (const textPart of textStream) {
            response += textPart;
        }

        clearTimeout(timeoutId);
        console.log("INFO: Chatbot response generated.");
        return response.trim() || "No response received.";
    } catch (error) {
        clearTimeout(timeoutId);
        console.error(`ERROR: Error generating chatbot response: ${error.message}`);
        return `An error occurred: ${error.message}`;
    }
};

/**
 * Express route handler for chatbot responses.
 */
exports.generateChatbotResponse = async function (req, res) {
    const { prompt, port } = req.body;

    if (!prompt) {
        return res.status(400).json({ error: "Prompt is required." });
    }

    try {
        const response = await exports.getChatbotResponse(prompt, port);
        return res.json({ response });
    } catch (error) {
        console.error(`ERROR: Error generating chatbot response: ${error.message}`);
        return res.status(500).json({ error: "An error occurred while processing your request." });
    }
};

// Unit Test Generation
// Function to refresh AI models (placeholder)
exports.refreshModel = async (req, res) => {
    try {
        exports.log("INFO", "🔄 Refreshing AI models...");
        return res.status(200).json({ message: "Models refreshed successfully." });
    } catch (error) {
        exports.log("ERROR", `❌ Error refreshing models: ${error.message}`);
        return res.status(500).json({ error: "Error refreshing AI models." });
    }
};

// Function to check server health
exports.checkServerHealth = (req, res) => {
    try {
        return res.status(200).json({ status: "✅ Server is up and running" });
    } catch (error) {
        exports.log("ERROR", `❌ Error checking server health: ${error.message}`);
        return res.status(500).json({ error: "Error checking server health." });
    }
};

// Exported helper function to generate unit tests for code
exports.generateUnitTestsForCode = async (code, language, port = 4000) => {
    const llamaSystemPrompt =
        `You are an AI assistant specializing in generating unit tests. ` +
        `Given the following code, generate unit tests that ensure the correctness of the code.`;

    // Ensure port is a valid number, defaulting to 4000 if invalid
    const validPort = Number.isNaN(Number(port)) ? 4000 : Number(port);

    const api = llamacpp.Api({
        baseUrl: {
            host: "localhost",
            port: validPort,
        },
    });

    try {
        const timeout = 5000; // 5 seconds timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        const textStream = await streamText({
            signal: controller.signal,
            model: llamacpp
                .CompletionTextGenerator({
                    api: api,
                    temperature: 0,
                    stopSequences: ["\n"],
                })
                .withInstructionPrompt(),
            prompt: {
                system: llamaSystemPrompt,
                instruction: `Please generate unit tests for the following ${language} code:\n\`\`\`${language}\n${code}\n\`\`\``,
                responsePrefix: "Unit Tests: ",
            },
        });

        let response = "";
        for await (const textPart of textStream) {
            response += textPart;
        }

        clearTimeout(timeoutId);
        return response;
    } catch (error) {
        exports.log("ERROR", `❌ Error generating unit tests: ${error.message}`);
        clearTimeout(timeoutId);
        return "An error occurred while generating unit tests.";
    }
};

// Exported controller function for handling chatbot generation request
// Function to generate unit tests for given code and language
exports.generateUnitTests = async (req, res) => {
    const { code, language, port } = req.body;

    if (!code || !language) {
        return res.status(400).json({ error: 'Code and language are required.' });
    }

    try {
        const unitTestResponse = await exports.generateUnitTestsForCode(code, language, port);
        return res.json({ unitTests: unitTestResponse });
    } catch (error) {
        exports.log("ERROR", `❌ Error generating unit tests: ${error.message}`);
        return res.status(500).json({ error: 'An error occurred while generating unit tests.' });
    }
};