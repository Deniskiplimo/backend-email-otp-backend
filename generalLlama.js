const { llamacpp, streamText } = require("modelfusion");
const axios = require("axios");

async function generalLlama(instruction, port) {
    // Define a more neutral and safe system prompt to avoid controversial issues
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
                return true; // Server is up, exit the function
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

    // Ensure the API setup is correct and points to the correct server and port
    const api = llamacpp.Api({
        baseUrl: {
            host: "localhost",  // Ensure the model server is running on localhost or adjust the host if necessary
            port: `${port}`,
        },
    });

    // Log the request details for debugging purposes
    console.log("Sending request to the model server...");
    console.log(`Instruction: ${instruction}`);
    console.log(`Server: http://localhost:${port}`);

    // Ensure server is available before proceeding
    const serverUrl = `http://localhost:${port}`;
    const isServerReady = await checkServerAvailability(serverUrl);

    if (!isServerReady) {
        console.error(`Failed to connect to the AI server at ${serverUrl}`);
        return;
    }

    try {
        // Set up the model's completion generator
        const textStream = await streamText({
            model: llamacpp
                .CompletionTextGenerator({
                    api: api, 
                    promptTemplate: llamacpp.prompt.ChatML, 
                    temperature: 0,  // Setting temperature to 0 for deterministic output
                })
                .withInstructionPrompt(),
            prompt: {
                system: llamaSystemPrompt,  // Safe system prompt
                instruction: instruction,   // User's instruction
            },
        });

        // Stream the model's response part by part and print it to the console
        for await (const textPart of textStream) {
            process.stdout.write(textPart);  // Write the output to the console
        }
        console.log("\nResponse completed.");
    } catch (error) {
        // Catch and log any errors that might occur during the process
        console.error("Error occurred while generating the response:", error);
    }
}

// Example usage of the generalLlama function
generalLlama("write about sustainable energy", 4000)
    .then(() => console.log("Request finished"))
    .catch((error) => console.error("Request failed:", error));
