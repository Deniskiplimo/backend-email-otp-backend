const { llamacpp, streamText } = require("modelfusion");
const axios = require("axios");

async function generalLlama(instruction, port, options = {}) {
    const llamaSystemPrompt =
        `You are an AI assistant designed to help with a wide range of topics. ` +
        `Please respond clearly and directly to all user instructions. ` +
        `Provide accurate and relevant information without being biased or offensive.`;

    // Function to check if the model server is available
    const checkServerAvailability = async (url, retries = 5, delayMs = 2000) => {
        for (let attempt = 1; attempt <= retries; attempt++) {
            try {
                await axios.get(url);
                console.log(`AI server is ready at ${url}`);
                return true; // Server is up
            } catch (error) {
                if (attempt < retries) {
                    console.log(`AI server not ready, retrying... (${attempt}/${retries})`);
                    await new Promise(resolve => setTimeout(resolve, delayMs)); // Wait before retrying
                } else {
                    console.error(`AI server not ready after ${retries} attempts`);
                    return false; // Server is still not available after retries
                }
            }
        }
    };

    const api = llamacpp.Api({
        baseUrl: {
            host: "localhost",  // Ensure the model server is running on localhost
            port: `${port}`,
        },
    });

    const serverUrl = `http://localhost:${port}`;
    const isServerReady = await checkServerAvailability(serverUrl);

    if (!isServerReady) {
        console.error(`Failed to connect to the AI server at ${serverUrl}`);
        return;
    }

    try {
        const textStream = await streamText({
            model: llamacpp
                .CompletionTextGenerator({
                    api: api,
                    temperature: 0,  // Setting temperature to 0 for deterministic output
                })
                .withInstructionPrompt(),
            prompt: {
                system: llamaSystemPrompt,
                instruction: instruction,  // Pass the user instruction
            },
        });

        let response = "";
        for await (const textPart of textStream) {
            response += textPart;
        }

        console.log("\nResponse completed.");
        return response;

    } catch (error) {
        console.error("Error occurred while generating the response:", error);
        return "An error occurred while processing the request.";
    }
}

// Example usage: Summarizing a lengthy document
generalLlama("Summarize the following article about sustainable energy.", 4000)
    .then((result) => console.log("\nGenerated Summary:\n", result))
    .catch((error) => console.error("❌ Request failed:", error));

// Example usage: Querying for external information via an API (e.g., weather data)
generalLlama("What is the current temperature in New York?", 4000)
    .then((result) => console.log("\nWeather Information:\n", result))
    .catch((error) => console.error("❌ Request failed:", error));
    module.exports = {  generalLlama };  
    

    // generalLlama.js
const exec = require('child_process').exec;

const generateCode = (language, instruction) => {
  return new Promise((resolve, reject) => {
    const command = `echo "Generate ${language} code: ${instruction}" | ./llamafile.exe -m tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf --n-predict 100`;
    
    exec(command, (error, stdout, stderr) => {
      if (error) reject(new Error(`Error: ${error.message}`));
      if (stderr) console.warn(`⚠️ Stderr: ${stderr}`);
      resolve(stdout.trim());
    });
  });
};

const summarizeText = (text) => {
  return new Promise((resolve, reject) => {
    const command = `echo "Summarize this: ${text}" | ./llamafile.exe -m tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf --n-predict 100`;
    
    exec(command, (error, stdout, stderr) => {
      if (error) reject(new Error(`Error: ${error.message}`));
      if (stderr) console.warn(`⚠️ Stderr: ${stderr}`);
      resolve(stdout.trim());
    });
  });
};

const translateText = (text, targetLanguage) => {
  return new Promise((resolve, reject) => {
    const command = `echo "Translate to ${targetLanguage}: ${text}" | ./llamafile.exe -m tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf --n-predict 100`;
    
    exec(command, (error, stdout, stderr) => {
      if (error) reject(new Error(`Error: ${error.message}`));
      if (stderr) console.warn(`⚠️ Stderr: ${stderr}`);
      resolve(stdout.trim());
    });
  });
};

module.exports = { generateCode, summarizeText, translateText };
