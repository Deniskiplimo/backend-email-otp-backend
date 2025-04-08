const { llamacpp, streamText } = require("modelfusion");
const axios = require("axios");
const { exec } = require("child_process");

// Function to check AI server availability
const checkServerAvailability = async (url, retries = 5, delayMs = 2000) => {
    for (let attempt = 1; attempt <= retries; attempt++) {
        try {
            await axios.get(url);
            console.log(`✅ AI server is ready at ${url}`);
            return true;
        } catch (error) {
            console.log(`⚠️ AI server not ready, retrying... (${attempt}/${retries})`);
            await new Promise(resolve => setTimeout(resolve, delayMs));
        }
    }
    console.error(`❌ AI server unavailable after ${retries} attempts`);
    return false;
};

// Function to interact with TinyLlama model
// Main function to generate AI response
async function generalLlama(instruction, port) {
    const llamaSystemPrompt = "You are an AI assistant designed to provide clear and direct responses.";
    const serverUrl = `http://localhost:${port}`;

    // Check if AI server is available
    const isServerReady = await checkServerAvailability(serverUrl);
    if (!isServerReady) {
        throw new Error(`❌ Failed to connect to AI server at ${serverUrl}`);
    }

    try {
        // Initialize Llama API
        const api = new llamacpp.Api({ baseUrl: `http://localhost:${port}` });

        // Generate AI response
        const textStream = await streamText({
            model: new llamacpp.CompletionTextGenerator({ api, temperature: 0 }).withInstructionPrompt(),
            prompt: { system: llamaSystemPrompt, instruction },
        });

        // Collect the response from the stream
        let response = "";
        for await (const textPart of textStream) {
            response += textPart;
        }

        return response.trim();
    } catch (error) {
        console.error("❌ AI response generation failed:", error.message);
        throw new Error("AI execution error: " + error.message);
    }
}


// Function to generate code using TinyLlama
const generateCode = (language, instruction) => {
    return new Promise((resolve, reject) => {
        const command = `echo "Generate ${language} code: ${instruction}" | ./llamafile.exe -m tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf --n-predict 100`;

        exec(command, (error, stdout, stderr) => {
            if (error) return reject(new Error(`Execution Error: ${error.message}`));
            if (stderr) console.warn(`⚠️ Stderr: ${stderr}`);
            resolve(stdout.trim());
        });
    });
};

// Function to summarize text
const summarizeText = (text) => {
    return new Promise((resolve, reject) => {
        const command = `echo "Summarize this: ${text}" | ./llamafile.exe -m tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf --n-predict 100`;

        exec(command, (error, stdout, stderr) => {
            if (error) return reject(new Error(`Execution Error: ${error.message}`));
            if (stderr) console.warn(`⚠️ Stderr: ${stderr}`);
            resolve(stdout.trim());
        });
    });
};

// Function to translate text
const translateText = (text, targetLanguage) => {
    return new Promise((resolve, reject) => {
        const command = `echo "Translate to ${targetLanguage}: ${text}" | ./llamafile.exe -m tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf --n-predict 100`;

        exec(command, (error, stdout, stderr) => {
            if (error) return reject(new Error(`Execution Error: ${error.message}`));
            if (stderr) console.warn(`⚠️ Stderr: ${stderr}`);
            resolve(stdout.trim());
        });
    });
};

module.exports = { generalLlama, generateCode, summarizeText, translateText };
