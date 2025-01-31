const { llamacpp, streamText } = require("modelfusion");

async function generalLlama(instruction, port) {
    // Define a more neutral and safe system prompt to avoid controversial issues
    const llamaSystemPrompt = 
    `You are an AI assistant designed to help with a wide range of topics. ` +
    `Please respond clearly and directly to all user instructions. ` +
    `Provide accurate and relevant information without being biased or offensive.`;

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
