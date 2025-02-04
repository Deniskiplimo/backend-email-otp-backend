const { llamacpp, streamText } = require("modelfusion");
const axios = require("axios");

// Simple cache to store responses for reuse (for short-term use)
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

// Function to generate code (existing)
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

        clearTimeout(timeoutId);
        return response;

    } catch (error) {
        console.error("❌ Error generating code:", error.message);
        clearTimeout(timeoutId);
        return "An error occurred while generating the response.";
    }
}

// Function to handle general chatbot responses
async function generalChatbotResponse(prompt, port) {
    const llamaSystemPrompt = "You are a helpful chatbot. Respond to the user's questions and requests in a friendly, informative manner.";

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
            process.stdout.write(textPart);
            response += textPart;
        }

        clearTimeout(timeoutId);
        return response;

    } catch (error) {
        console.error("❌ Error generating chatbot response:", error.message);
        clearTimeout(timeoutId);
        return "An error occurred while generating the response.";
    }
}

// Function to explain code (new)
async function explainCode(code, language, port) {
    const llamaSystemPrompt =
        `You are a helpful AI that explains code. ` +
        `Please explain the following code in detail, line by line, to help the user understand how it works.`;

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
                instruction: `Please explain the following code in ${language}:\n\`\`\`${language}\n${code}\n\`\`\``,
                responsePrefix: "Explanation: ",
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
        console.error("❌ Error explaining code:", error.message);
        clearTimeout(timeoutId);
        return "An error occurred while explaining the code.";
    }
}

// Function to debug code (new)
async function debugCode(code, language, port) {
    const llamaSystemPrompt =
        `You are an AI assistant specializing in debugging code. ` +
        `Please identify any issues with the following code and suggest improvements or fixes.`;

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
                instruction: `Please debug the following ${language} code:\n\`\`\`${language}\n${code}\n\`\`\``,
                responsePrefix: "Debugging suggestion: ",
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
        console.error("❌ Error debugging code:", error.message);
        clearTimeout(timeoutId);
        return "An error occurred while debugging the code.";
    }
}

// Response Caching (example use case)
async function getCachedResponse(key) {
    if (responseCache[key]) {
        console.log("✅ Returning cached response");
        return responseCache[key];
    }
    return null;
}

// Function to generate unit tests for code (new)
async function generateUnitTestsForCode(code, language, port) {
    const llamaSystemPrompt =
        `You are an AI assistant specializing in generating unit tests. ` +
        `Given the following code, generate unit tests that ensure the correctness of the code.`;

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
}
// Function to handle general chatbot responses
async function generalChatbotResponse(prompt, port) {
    const llamaSystemPrompt = "You are a helpful chatbot. Respond to the user's questions and requests in a friendly, informative manner.";

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
            process.stdout.write(textPart);
            response += textPart;
        }

        clearTimeout(timeoutId);
        // Check the server health before interacting with the chat API
        if (await checkServerHealth()) {
            const apiResponse = await sendMessageToChatAPI(response);
            return apiResponse; // Send the chatbot's response to the API
        }

        return response;

    } catch (error) {
        console.error("❌ Error generating chatbot response:", error.message);
        clearTimeout(timeoutId);
        return "An error occurred while generating the response.";
    }
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
    refactorCode,
    generalChatbotResponse,
    sendMessageToChatAPI,
    explainCode,
    debugCode,
    checkServerAvailability,
    checkServerHealth,
    getCachedResponse,
    generateUnitTestsForCode,
};
