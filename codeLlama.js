const { llamacpp, streamText } = require("modelfusion");
const axios = require("axios");

// Simple cache to store responses for reuse (with expiration)
const responseCache = {};

// Function to check if the server is available
async function checkServerAvailability(port) {
    const serverUrl = `http://localhost:${port}`;
    try {
        await axios.get(serverUrl);
        console.log(`✅ AI server is ready at ${serverUrl}`);
        return true;
    } catch (error) {
        console.error(`❌ Server is unavailable at ${serverUrl}`);
        return false;
    }
}

// Function to check the health of the server
async function checkServerHealth() {
    try {
        // Check health endpoint (can be customized)
        const response = await axios.get('http://localhost:4000/health');
        if (response.status === 200) {
            console.log("✅ Server is up and running");
            return true;
        }
        return false;
    } catch (error) {
        console.error("❌ Server health check failed");
        return false;
    }
}

// Retry logic with exponential backoff
async function withRetry(func, retries = 3, delay = 2000) {
    let attempt = 0;
    while (attempt < retries) {
        try {
            return await func();
        } catch (error) {
            attempt++;
            if (attempt < retries) {
                const backoffDelay = delay * Math.pow(2, attempt); // Exponential backoff
                console.log(`Retrying (${attempt}/${retries}) after ${backoffDelay / 1000}s...`);
                await new Promise(resolve => setTimeout(resolve, backoffDelay));
            } else {
                console.error(`All ${retries} attempts failed. Returning error message.`);
                throw new Error(`Failed after ${retries} attempts`);
            }
        }
    }
}

// Enhanced code generation function
async function codeLlama(instruction, language, port, retries = 3, timeout = 5000, debug = false) {
    const llamaSystemPrompt = `You are an AI assistant here to help with programming tasks. Your responses will be clear, concise, and code-oriented.`;

    const api = llamacpp.Api({
        baseUrl: {
            host: "localhost",
            port: Number(port),
        },
    });

    // Ensure the language is supported
    const supportedLanguages = ["javascript", "python", "java", "go", "cpp", "ruby"];
    if (!supportedLanguages.includes(language.toLowerCase())) {
        return `Language "${language}" is not supported. Supported languages are: ${supportedLanguages.join(", ")}.`;
    }

    const modelConfig = llamacpp.CompletionTextGenerator({
        api: api,
        temperature: 0.7,
        stopSequences: ["\n```"],
    }).withInstructionPrompt();

    const requestPayload = {
        system: llamaSystemPrompt,
        instruction: instruction,
        responsePrefix: `Here is the program in ${language}:\n\`\`\`${language}\n`,
    };

    const fetchRequest = async () => {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), timeout);

            const textStream = await streamText({
                signal: controller.signal,
                model: modelConfig,
                prompt: requestPayload,
            });

            let response = "";
            for await (const textPart of textStream) {
                if (debug) console.log(`Generated: ${textPart}`);  // Optional debugging output
                response += textPart;
            }

            clearTimeout(timeoutId);
            return response;

        } catch (error) {
            clearTimeout(timeoutId);
            if (debug) console.error("Error details:", error);
            throw new Error(error.message || "An error occurred while generating the response.");
        }
    };

    // Retry logic for transient failures
    try {
        return await withRetry(fetchRequest, retries);
    } catch (error) {
        return `Failed to generate code after ${retries} attempts. Please try again later.`;
    }
}

// General chatbot response function
async function generalChatbotResponse(prompt, port, retries = 3, timeout = 5000, debug = false) {
    const llamaSystemPrompt = "You are a helpful chatbot. Respond to the user's questions and requests in a friendly, informative manner.";

    const api = llamacpp.Api({
        baseUrl: {
            host: "localhost",
            port: Number(port),
        },
    });

    const fetchResponse = async () => {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        const textStream = await streamText({
            signal: controller.signal,
            model: llamacpp
                .CompletionTextGenerator({
                    api: api,
                    temperature: 0.7,
                    stopSequences: ["\n"],
                })
                .withInstructionPrompt(),
            prompt: {
                system: llamaSystemPrompt,
                instruction: prompt,
                responsePrefix: "Chatbot: ",
            },
        });

        let response = "";
        for await (const textPart of textStream) {
            response += textPart;
        }

        clearTimeout(timeoutId);
        return response;
    };

    try {
        // Retry the request if it fails due to transient issues
        return await withRetry(fetchResponse, retries);
    } catch (error) {
        console.error("❌ Error generating chatbot response:", error.message);
        return "An error occurred while generating the response.";
    }
}

// Response Caching (with expiration)
async function getCachedResponse(key) {
    if (responseCache[key] && Date.now() - responseCache[key].timestamp < 3600000) { // Cache expiration after 1 hour
        console.log("✅ Returning cached response");
        return responseCache[key].data;
    }
    return null;
}

async function cacheResponse(key, data) {
    responseCache[key] = {
        data,
        timestamp: Date.now(),
    };
}
// Function to send a chat message to the API
async function sendMessageToChatAPI(message) {
    const apiUrl = 'http://localhost:3000/api/chat'; // Endpoint for your chat API

    try {
        const response = await axios.post(apiUrl, {
            message: message, // Send the message to the API
        });

        // Process the response from the API
        if (response.status === 200) {
            console.log("API Response: ", response.data);
            return response.data; // Return the API response
        } else {
            console.error("❌ Failed to get response from the chat API.");
            return "An error occurred while communicating with the chat API.";
        }
    } catch (error) {
        console.error("❌ Error sending message to chat API:", error.message);
        return "An error occurred while sending the message to the chat API.";
    }
}
// Function to refactor code (new)
async function refactorCode(code, language, port) {
    const llamaSystemPrompt =
        `You are an AI assistant specialized in refactoring code. ` +
        `Please refactor the following code in ${language} to make it more efficient, readable, or maintainable.`;

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
                instruction: `Please refactor the following ${language} code:\n\`\`\`${language}\n${code}\n\`\`\``,
                responsePrefix: "Refactored code: ",
            },
        });

        let response = "";
        for await (const textPart of textStream) {
            response += textPart;
        }

        clearTimeout(timeoutId);
        return response;

    } catch (error) {
        console.error("❌ Error refactoring code:", error.message);
        clearTimeout(timeoutId);
        return "An error occurred while refactoring the code.";
    }
} 
 
// Export functions for external use
module.exports = { 
    codeLlama,
    generalChatbotResponse,
    sendMessageToChatAPI,
    checkServerAvailability,
    checkServerHealth,
    getCachedResponse,
    cacheResponse,
};
