// Import necessary functions from your codeLlama utility
const {
    codeLlama, 
    explainCode, 
    debugCode, 
    refactorCode, 
    convertCodeLanguage, 
    validateCodeSyntax,
    chatWithModel,
    summarizeText,
    generateUnitTest,
    processUtterance
} = require("../codeLlama");
const { llamacpp, streamText } = require("modelfusion");

// General function to handle errors
const handleError = (res, error, message = "An error occurred") => {
    console.error(error);
    res.status(500).json({ error: message });
};

// Helper function to check if required parameters are provided
const checkRequiredParams = (params, res) => {
    for (const [key, value] of Object.entries(params)) {
        if (!value) {
            return res.status(400).json({ error: `${key} is required.` });
        }
    }
    return null;
};
// Handle code generation request
async function handleCodeLlamaRequest(instruction, language, port) {
    if (!instruction || !language) {
        // Respond with a clear error if required fields are missing
        throw new Error("Instruction and language are required.");
    }

    const llamaSystemPrompt = `You are an AI assistant for programming tasks. Generate code in the specified language.`;

    const api = llamacpp.Api({ baseUrl: `http://localhost:${port}` });
    console.log(`🔄 Sending request to model server (Port: ${port})...`);

    try {
        const timeout = 5000;  // 5-second timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        // Use llamacpp to interact with the model for code generation
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
            response += textPart;
        }

        clearTimeout(timeoutId);
        console.log("\n✅ Response completed.");
        return response;
    } catch (error) {
        console.error("❌ Error generating code:", error.message);
        return `An error occurred while generating the response: ${error.message}`;
    }
}


// Handle explaining code
async function handleExplainCodeRequest(req, res) {
    const { code, language } = req.body;
    const errorResponse = checkRequiredParams({ code, language }, res);
    if (errorResponse) return errorResponse;

    try {
        const response = await explainCode(code, language, 4000);
        res.json({ result: response });
    } catch (error) {
        handleError(res, error, "Failed to explain code.");
    }
}

// Handle debugging code
async function handleDebugCodeRequest(req, res) {
    const { code, language } = req.body;
    const errorResponse = checkRequiredParams({ code, language }, res);
    if (errorResponse) return errorResponse;

    try {
        const response = await debugCode(code, language, 4000);
        res.json({ result: response });
    } catch (error) {
        handleError(res, error, "Failed to debug code.");
    }
}

// Handle refactoring code
async function handleRefactorCodeRequest(req, res) {
    const { code, language } = req.body;
    const errorResponse = checkRequiredParams({ code, language }, res);
    if (errorResponse) return errorResponse;

    try {
        const response = await refactorCode(code, language, 4000);
        if (!response || response.trim() === "") {
            return res.status(500).json({ error: "Refactoring failed. No changes were detected." });
        }
        res.json({ result: response });
    } catch (error) {
        handleError(res, error, "Failed to refactor code.");
    }
}



// Handle converting code language
async function handleConvertCodeLanguageRequest(req, res) {
    const { code, fromLanguage, toLanguage } = req.body;
    const errorResponse = checkRequiredParams({ code, fromLanguage, toLanguage }, res);
    if (errorResponse) return errorResponse;

    // Log the received code, fromLanguage, and toLanguage for debugging purposes
    console.log(`Converting code from ${fromLanguage} to ${toLanguage}`);
    console.log(`Code: ${code}`);

    // Setup Llama model communication
    const LLAMA_PORT = 4000;
    const llamaSystemPrompt = `You are an AI assistant for programming tasks. Convert the provided code from ${fromLanguage} to ${toLanguage}.`;

    const api = llamacpp.Api({ baseUrl: `http://localhost:${LLAMA_PORT}` });

    try {
        // Timeout setup to prevent long responses
        const timeout = 5000;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        // Stream the result from Llama API
        const textStream = await streamText({
            signal: controller.signal,
            model: llamacpp
                .CompletionTextGenerator({ api, temperature: 0, stopSequences: ["\n"] })
                .withInstructionPrompt(),
            prompt: {
                system: llamaSystemPrompt,
                instruction: code,
                responsePrefix: `Here is the converted code in ${toLanguage}:\n`,
            },
        });

        let response = "";
        for await (const textPart of textStream) {
            process.stdout.write(textPart);
            response += textPart;
        }

        clearTimeout(timeoutId);
        console.log("\n✅ Code conversion completed.");

        // If the response is empty, handle it as an error
        if (!response || response.trim() === "") {
            return res.status(400).json({ error: "Conversion failed or no response from model." });
        }

        // Respond with the converted code
        res.json({ result: response });
    } catch (error) {
        // Detailed error logging for debugging
        console.error("Error during code conversion:", error);

        // Send a more specific error message in the response
        res.status(500).json({ error: `Failed to convert code language. ${error.message}` });
    }
}


// Handle validating code syntax
async function handleValidateCodeSyntaxRequest(req, res) {
    const { code, language } = req.body;
    const errorResponse = checkRequiredParams({ code, language }, res);
    if (errorResponse) return errorResponse;

    // Log the received code and language for debugging purposes
    console.log(`Validating syntax for code: ${code} | Language: ${language}`);

    // Setup Llama model communication
    const LLAMA_PORT = 4000;
    const llamaSystemPrompt = `You are an AI assistant for programming tasks. Validate the syntax of the provided code in ${language}.`;

    const api = llamacpp.Api({ baseUrl: `http://localhost:${LLAMA_PORT}` });

    try {
        // Timeout setup to prevent long responses
        const timeout = 5000;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        // Stream the validation result from the Llama model
        const textStream = await streamText({
            signal: controller.signal,
            model: llamacpp
                .CompletionTextGenerator({ api, temperature: 0, stopSequences: ["\n"] })
                .withInstructionPrompt(),
            prompt: {
                system: llamaSystemPrompt,
                instruction: code,
                responsePrefix: `Here is the validation result for the ${language} code:\n`,
            },
        });

        let response = "";
        for await (const textPart of textStream) {
            process.stdout.write(textPart);
            response += textPart;
        }

        clearTimeout(timeoutId);
        console.log("\n✅ Syntax validation completed.");

        // If the response is empty, handle it as an error
        if (!response || response.trim() === "") {
            return res.status(400).json({ error: "Invalid code or no response from model." });
        }

        // Respond with the result from validation
        res.json({ result: response });
    } catch (error) {
        // Detailed error logging for debugging
        console.error("Error during syntax validation:", error);

        // Send a more specific error message in the response
        res.status(500).json({ error: `Failed to validate code syntax. ${error.message}` });
    }
}

// Handle chat functionality
async function handleChatRequest(req, res) {
    const { message } = req.body;
    if (!message) {
        return res.status(400).json({ error: "Message is required." });
    }

    try {
        const response = await chatWithModel(message, 4000);
        res.json({ result: response });
    } catch (error) {
        handleError(res, error, "Failed to process the chat request.");
    }
}

// Handle summarizing text
async function handleSummarizeRequest(req, res) {
    const { text } = req.body;
    if (!text) {
        return res.status(400).json({ error: "Text is required." });
    }

    try {
        const response = await summarizeText(text, 4000);
        res.json({ result: response });
    } catch (error) {
        handleError(res, error, "Failed to summarize the text.");
    }
}

// Handle generating unit tests for code
async function handleGenerateUnitTestRequest(req, res) {
    const { code, language } = req.body;
    const errorResponse = checkRequiredParams({ code, language }, res);
    if (errorResponse) return errorResponse;

    try {
        const response = await generateUnitTest(code, language, 4000);
        res.json({ result: response });
    } catch (error) {
        handleError(res, error, "Failed to generate unit test.");
    }
}

// Handle utterance (speech to text)
async function handleUtteranceRequest(req, res) {
    const { utterance } = req.body;
    if (!utterance) {
        return res.status(400).json({ error: "Utterance is required." });
    }

    try {
        const response = await processUtterance(utterance, 4000);
        res.json({ result: response });
    } catch (error) {
        handleError(res, error, "Failed to process the utterance.");
    }
}

// Exporting all the controller functions
module.exports = {
    handleCodeLlamaRequest,
    handleExplainCodeRequest,
    handleDebugCodeRequest,
    handleRefactorCodeRequest,
    handleConvertCodeLanguageRequest,
    handleValidateCodeSyntaxRequest,
    handleChatRequest,
    handleSummarizeRequest,
    handleGenerateUnitTestRequest,
    handleUtteranceRequest
};
