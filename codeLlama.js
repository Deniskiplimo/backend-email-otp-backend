const { llamacpp, streamText } = require("modelfusion");

async function codeLlama(instruction, language, port) {
    // Define a simpler and more neutral system prompt to avoid conflicts.
    const llamaSystemPrompt =
    `You are an AI assistant here to help with programming tasks. ` +
    `Your responses will be clear, concise, and code-oriented.` +
    `Please follow the instructions and generate the requested code in the specified language.`;

    // Ensure the API setup is correct and points to the right server
    const api = llamacpp.Api({
        baseUrl: {
            host: "localhost",  // Adjust if the server is not on localhost
            port: `${port}`,
        },
    });

    // Log the initial state and input to help with debugging
    console.log("Sending request to the model server...");
    console.log(`Instruction: ${instruction}`);
    console.log(`Language: ${language}`);
    console.log(`Server: http://localhost:${port}`);

    try {
        // Set up the model's completion generator with necessary parameters
        const textStream = await streamText({
            model: llamacpp
                .CompletionTextGenerator({
                    api: api, 
                    promptTemplate: llamacpp.prompt.ChatML, 
                    temperature: 0,  // Set temperature to 0 for deterministic output
                    stopSequences: ["\n```"],  // Stop sequence for code blocks
                })
                .withInstructionPrompt(),
            prompt: {
                system: llamaSystemPrompt,  // System prompt that defines model behavior
                instruction: instruction,   // Instruction for the model to process
                responsePrefix: `Here is the program in ${language}:\n\`\`\`${language}\n`, // Code block format
            },
        });

        // Stream the model's response part by part and print it to the console
        for await (const textPart of textStream) {
            process.stdout.write(textPart);  // Write to stdout (console)
        }
        console.log("\nResponse completed.");
    } catch (error) {
        // Catch and log any errors that occur during the process
        console.error("Error occurred while generating code:", error);
    }
}

// Example usage:
codeLlama("create a CNN model", "python", 4000)
    .then(() => console.log("Request finished"))
    .catch((error) => console.error("Request failed:", error));
