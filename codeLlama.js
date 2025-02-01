const { llamacpp, streamText } = require("modelfusion");

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
                    temperature: 0.7,  // Slightly higher for more creative answers
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

// Export the functions to be used elsewhere
module.exports = {
    codeLlama,
    generalChatbotResponse,
    explainCode,
    debugCode,
};
