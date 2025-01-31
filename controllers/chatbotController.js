const { llamacpp, streamText } = require("modelfusion");

// Function to handle AI responses for generic and programming-related tasks
exports.getAIResponse = async (req, res) => {
  try {
    const { prompt, language, port } = req.body;

    // Check if prompt is provided
    if (!prompt) {
      return res.status(400).json({ error: 'Prompt is required' });
    }

    // Check if port is provided
    if (!port) {
      return res.status(400).json({ error: 'Port is required' });
    }

    console.log("Received port:", port); // Debugging line to check the port value

    // Handle programming-related requests (CodeLlama)
    if (prompt.toLowerCase().includes('create') || prompt.toLowerCase().includes('generate')) {
      if (!language) {
        return res.status(400).json({ error: 'Language is required for programming tasks' });
      }

      // Call codeLlama for programming-related instructions
      const response = await codeLlama(prompt, language, port);
      return res.status(200).json({ response });

    } else {
      // Handle general chatbot responses (non-programming related)
      const response = await getChatbotResponse(prompt, port);  // Pass port to getChatbotResponse
      return res.status(200).json({ response });
    }
  } catch (error) {
    console.error('AI Response error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Function to handle chatbot responses (general)
async function getChatbotResponse(prompt, port) {
  console.log("Using port:", port); // Debugging line to check the port value

  // Simulate chatbot response (you can replace this with actual AI logic)
  return `Chatbot response to: ${prompt}`;
}

// CodeLlama function for programming-related tasks
async function codeLlama(instruction, language, port) {
  const llamaSystemPrompt =
  `You are an AI assistant here to help with programming tasks. ` +
  `Your responses will be clear, concise, and code-oriented.` +
  `Please follow the instructions and generate the requested code in the specified language.`;

  const api = llamacpp.Api({
    baseUrl: {
      host: "localhost",  
      port: port || 4000,  // Fallback to 4000 if port is undefined
    },
  });

  console.log("Sending request to the model server...");
  console.log(`Instruction: ${instruction}`);
  console.log(`Language: ${language}`);
  console.log(`Server: http://localhost:${port}`);

  try {
    const textStream = await streamText({
      model: llamacpp
        .CompletionTextGenerator({
          api: api, 
          promptTemplate: llamacpp.prompt.ChatML, 
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

    let fullResponse = '';
    for await (const textPart of textStream) {
      fullResponse += textPart;
    }

    return fullResponse;
  } catch (error) {
    console.error("Error occurred while generating code:", error);
    throw error;
  }
}

// Export the individual functions for easier testing or usage elsewhere
exports.getChatbotResponse = getChatbotResponse;
exports.codeLlama = codeLlama;
