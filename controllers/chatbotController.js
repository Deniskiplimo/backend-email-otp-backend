const { codeLlama: importedCodeLlama } = require('../codeLlama');
const { generalLlama } = require('../generalLlama');
const { llamacpp, streamText } = require("modelfusion");
const axios = require('axios');

// Default AI model server port (falling back to an environment variable if available)
const DEFAULT_PORT = process.env.AI_SERVER_PORT || 4000; // Pick the port from environment or default to 4000

// Function to fetch the running port dynamically (if required, from server config or environment)
function getRunningPort() {
    // If the server is already running and bound to a port, you can dynamically fetch it from the environment or a server config.
    return process.env.AI_SERVER_PORT || DEFAULT_PORT; // Defaults to 4000 if not specified
}

// Function to fetch AI response from the server
async function fetchAIResponseFromServer(instruction, language, port = getRunningPort()) {
    const url = `http://127.0.0.1:${port}/`;  // AI server URL

    try {
        const response = await axios.post(url, {
            prompt: instruction,
            language: language,
            port: port
        });
        return response.data.response;
    } catch (error) {
        console.error('❌ Error fetching response from AI server:', error.message);
        return "Error occurred while contacting AI model server.";
    }
}

// Function to handle AI responses from the client
exports.getAIResponse = async (req, res) => {
    let { prompt, instruction, language, port } = req.body;

    prompt = prompt || instruction;
    port = Number(port) || getRunningPort();  // Pick the running port

    if (!prompt || typeof prompt !== "string" || prompt.trim() === "") {
        return res.status(400).json({ error: 'Prompt is required and must be a non-empty string' });
    }

    if (!isValidPort(port)) {
        return res.status(400).json({ error: 'Invalid port number' });
    }

    logRequest('Received AI request', { prompt, language, port });

    try {
        let response;

        if (isProgrammingTask(prompt)) {
            language = language || "python"; // Default to Python if missing
            logRequest('Programming request detected', { prompt, language });

            // Handle programming-related tasks with importedCodeLlama
            response = await importedCodeLlama(prompt, language, port);
        } else {
            logRequest('General chatbot request detected', { prompt });

            // Use generalLlama for non-programming related tasks
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

// Function to interact with the AI model for programming-related tasks
async function codeLlama(instruction, language, port) {
    const llamaSystemPrompt =
        `You are an AI assistant here to help with programming tasks. ` +
        `Your responses will be clear, concise, and code-oriented. ` +
        `Please follow the instructions and generate the requested code in the specified language.`;

    const api = llamacpp.Api({
        baseUrl: {
            host: "localhost",
            port: Number(port),
        },
    });

    console.log("Sending request to the model server...");
    console.log(`Instruction: ${instruction}`);
    console.log(`Language: ${language}`);
    console.log(`Server: http://localhost:${port}`);

    try {
        const timeout = 5000;  // Set a timeout for the request to prevent infinite loading
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        const textStream = await streamText({
            signal: controller.signal,  // Attach abort controller signal for timeout
            model: llamacpp
                .CompletionTextGenerator({
                    api: api,
                    temperature: 0,
                    stopSequences: ["\n```"],
                })
                .withInstructionPrompt(),
            prompt: {
                system: llamaSystemPrompt,
                instruction: instruction,
                responsePrefix: `Here is the program in ${language}:\n\`\`\`${language}\n`,
            },
        });

        let response = "";
        for await (const textPart of textStream) {
            process.stdout.write(textPart);
            response += textPart;
        }

        console.log("\nResponse completed.");
        clearTimeout(timeoutId);  // Cleanup timeout after request completion
        return response;

    } catch (error) {
        console.error("❌ Error generating code:", error.message);
        clearTimeout(timeoutId);  // Cleanup timeout in case of an error
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
// Code refactoring, optimization, unit testing, and algorithm suggestion
// Exported function to refactor the code for better readability or performance
exports.refactorCode = async (code, language, port = 4000) => {
    const llamaSystemPrompt =
        `You are an AI assistant specializing in code refactoring. ` +
        `Your task is to improve the given code, making it more efficient or readable while maintaining the original functionality.`;

    const api = llamacpp.Api({
        baseUrl: {
            host: "localhost",
            port: Number(port) || 4000,  // Default to 4000 if port is undefined or invalid
        },
    });

    try {
        const timeout = 5000;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        // Stream the result from the API
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
                instruction: `Please refactor the following ${language} code for better readability or performance:\n\`\`\`${language}\n${code}\n\`\`\``,
                responsePrefix: "Refactored code: ",
            },
        });

        let response = "";
        // Handle each chunk of text from the stream
        for await (const textPart of textStream) {
            // Append to the response text and handle stream correctly
            response += textPart;
        }

        clearTimeout(timeoutId); // Clear the timeout if the stream finishes
        return response || "No refactored code returned."; // Ensure something is returned

    } catch (error) {
        clearTimeout(timeoutId); // Clear timeout on error
        console.error("❌ Error refactoring code:", error.message);
        return `An error occurred while refactoring the code: ${error.message}`; // Provide error message
    }
};

// Exported function to optimize the code for better performance
exports.optimizeCode = async (code, language, port) => {
    const llamaSystemPrompt =
        `You are an AI assistant specializing in code optimization. ` +
        `Your task is to improve the performance of the given code by reducing time complexity or memory usage.`;

    const api = llamacpp.Api({
        baseUrl: {
            host: "localhost",
            port: Number(port),
        },
    });

    try {
        const timeout = 5000;
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
                instruction: `Please optimize the following ${language} code for better performance (e.g., reduce time complexity, improve memory usage):\n\`\`\`${language}\n${code}\n\`\`\``,
                responsePrefix: "Optimized code: ",
            },
        });

        let response = "";
        for await (const textPart of textStream) {
            process.stdout.write(textPart);
            response += textPart;
        }

        clearTimeout(timeoutId);
        return response;

    } catch (error) {
        console.error("❌ Error optimizing code:", error.message);
        clearTimeout(timeoutId);
        return "An error occurred while optimizing the code.";
    }
};


// Algorithm Suggestion
// Exported function to suggest an algorithm for a given problem
exports.suggestAlgorithm = async (problemDescription, port = 4000) => { 
    const llamaSystemPrompt =
        `You are an AI assistant specializing in algorithm design. ` +
        `Given a problem description, suggest an appropriate algorithm or approach to solve it.`;

    // Ensure port is a valid number, defaulting to 4000 if invalid
    const validPort = Number.isNaN(Number(port)) ? 4000 : Number(port);

    const api = llamacpp.Api({
        baseUrl: {
            host: "localhost",
            port: validPort,
        },
    });

    let timeoutId; // Declare timeoutId outside the try block

    try {
        const timeout = 5000;
        const controller = new AbortController();
        timeoutId = setTimeout(() => controller.abort(), timeout); // Assign timeoutId here

        const textStream = await streamText({
            signal: controller.signal,
            model: llamacpp.CompletionTextGenerator({
                api: api,
                temperature: 0,
                stopSequences: ["\n"],
            }).withInstructionPrompt(),
            prompt: {
                system: llamaSystemPrompt,
                instruction: `Suggest an algorithm or approach to solve the following problem:\n${problemDescription}`,
                responsePrefix: "Suggested Algorithm: ",
            },
        });

        let response = "";
        for await (const textPart of textStream) {
            process.stdout.write(textPart);
            response += textPart;
        }

        clearTimeout(timeoutId); // Clear timeout here
        return response;

    } catch (error) {
        console.error("❌ Error suggesting algorithm:", error.message);
        if (timeoutId) clearTimeout(timeoutId); // Clear timeout if it exists
        return "An error occurred while suggesting an algorithm.";
    }
};

// Function to handle AI responses from the client
exports.getAIResponse = async (req, res) => {
    let { prompt, instruction, language, port } = req.body;

    prompt = prompt || instruction;
    port = Number(port) || DEFAULT_PORT; // Ensure port is a number

    if (!prompt || typeof prompt !== "string" || prompt.trim() === "") {
        return res.status(400).json({ error: 'Prompt is required and must be a non-empty string' });
    }

    if (!isValidPort(port)) {
        return res.status(400).json({ error: 'Invalid port number' });
    }

    logRequest('Received AI request', { prompt, language, port });

    try {
        let response;

        if (isProgrammingTask(prompt)) {
            language = language || "python"; // Default to Python if missing
            logRequest('Programming request detected', { prompt, language });

            // Handle programming-related tasks with importedCodeLlama
            response = await importedCodeLlama(prompt, language, port);
        } else {
            logRequest('General chatbot request detected', { prompt });

            // Use generalLlama for non-programming related tasks
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

// Function to refresh AI models (can be used to trigger model refresh)
exports.refreshModel = async (req, res) => {
    try {
        console.log('🔄 Refreshing AI models...');
        return res.status(200).json({ message: 'Models refreshed successfully' });
    } catch (error) {
        console.error('❌ Error refreshing models:', error);
        return res.status(500).json({ error: 'Error refreshing AI models' });
    }
};

// Function to check server health
exports.checkServerHealth = (req, res) => {
    try {
        return res.status(200).json({ status: '✅ Server is up and running' });
    } catch (error) {
        console.error('❌ Error checking server health:', error);
        return res.status(500).json({ error: 'Error checking server health' });
    }
};
// Function to log requests and responses (replace with your actual logging system)


// Exported function to generate chatbot responses
exports.getChatbotResponse = async (prompt, port) => {
    const timeout = 5000;  // 5 seconds timeout for AI response
    const controller = new AbortController();  // Create an AbortController instance
    const timeoutId = setTimeout(() => controller.abort(), timeout);  // Set the timeout

    try {
        logRequest('Generating chatbot response', { prompt });

        const serverUrl = `http://localhost:${port}`;
        const api = llamacpp.Api({
            baseUrl: {
                host: "localhost",
                port: `${port}`,
            },
        });

        // Exported function to check if the server is available
        exports.checkServerAvailability = async () => {
            try {
                await axios.get(serverUrl);
                console.log(`AI server is ready at ${serverUrl}`);
                return true;
            } catch (error) {
                console.error(`Server is unavailable at ${serverUrl}`);
                return false;
            }
        };

        const isServerReady = await exports.checkServerAvailability();
        if (!isServerReady) {
            return 'Server is unavailable. Please try again later.';
        }

        // Proceed with model response generation if server is available
        const textStream = await streamText({
            model: llamacpp.CompletionTextGenerator({
                api: api,
                temperature: 0,  // Set temperature to 0 for deterministic output
            }).withInstructionPrompt(),
            prompt: {
                system: `You are an AI assistant designed to help with a wide range of topics. Please respond clearly and directly.`,
                instruction: prompt,  // Use user input for the instruction
            },
        });

        let response = '';
        for await (const textPart of textStream) {
            response += textPart;
        }

        // Clear timeout once the response is received
        clearTimeout(timeoutId);

        logRequest("Chatbot response generated", { response });

        return response;

    } catch (error) {
        // Handle errors including timeout
        clearTimeout(timeoutId);  // Ensure timeout is cleared
        console.error('❌ Error generating chatbot response:', error);
        return "An error occurred while generating the response.";
    }
};

// Exported function to handle chatbot response generation via API
exports.generateChatbotResponse = async (req, res) => {
    const { prompt, port } = req.body;  // Extract the prompt and port from the request body
    
    if (!prompt || !port) {
        return res.status(400).json({ error: 'Prompt and port are required.' });
    }

    try {
        // Generate the chatbot response
        const response = await exports.getChatbotResponse(prompt, port);
        
        // Send the generated response back as JSON
        return res.json({ response });
    } catch (error) {
        console.error('Error generating chatbot response:', error);
        
        // Send a 500 error response if something goes wrong
        return res.status(500).json({ error: 'An error occurred while processing your request.' });
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
        console.error("❌ Error generating unit tests:", error.message);
        clearTimeout(timeoutId);
        return "An error occurred while generating unit tests.";
    }
};


// Exported controller function for handling chatbot generation request
exports.generateUnitTestsForCode = async (code, language, port = 4000) => {
    const llamaSystemPrompt =
        `You are an AI assistant specializing in writing unit tests. ` +
        `Your task is to generate comprehensive unit tests for the given ${language} code.`;

    const api = llamacpp.Api({
        baseUrl: {
            host: "localhost",
            port: Number(port) || 4000, // Default to 4000 if port is undefined or invalid
        },
    });

    let timeoutId = null; // Declare timeoutId to prevent ReferenceError

    try {
        const timeout = 5000;
        const controller = new AbortController();
        timeoutId = setTimeout(() => {
            console.error("❌ Timeout: Request took too long, aborting...");
            controller.abort();
        }, timeout); // Assign timeoutId

        console.log("✅ Requesting unit tests...");

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
                responsePrefix: "Generated unit tests: ",
            },
        });

        let response = "";
        for await (const textPart of textStream) {
            if (!textPart) break; // Ensure it doesn't loop infinitely
            console.log("📝 Received:", textPart);
            response += textPart;
        }

        clearTimeout(timeoutId);
        console.log("✅ Response complete.");
        return response || "No response received."; // Handle empty response case

    } catch (error) {
        console.error("❌ Error generating unit tests:", error.message);
        if (timeoutId) clearTimeout(timeoutId); // Ensure timeout is cleared in case of error
        return "An error occurred while generating unit tests.";
    }
};

// Express route handler to process API requests for generating unit tests
exports.generateUnitTests = async (req, res) => {
    const { code, language, port } = req.body;  // Extract the code, language, and port from the request body

    if (!code || !language || !port) {
        return res.status(400).json({ error: 'Code, language, and port are required.' });
    }

    try {
        // Generate the unit tests by calling the helper function
        const unitTestResponse = await exports.generateUnitTestsForCode(code, language, port);
        
        // Send the generated unit test response back as JSON
        return res.json({ unitTests: unitTestResponse });
    } catch (error) {
        console.error('Error generating unit tests:', error);
        
        // Send a 500 error response if something goes wrong
        return res.status(500).json({ error: 'An error occurred while generating unit tests.' });
    }
};



