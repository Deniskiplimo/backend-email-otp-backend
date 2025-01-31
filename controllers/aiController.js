const { streamText } = require("modelfusion");

exports.getAIResponse = async (req, res) => {
  try {
    const { prompt } = req.body;
    if (!prompt) return res.status(400).json({ error: 'Prompt is required' });

    // Stream the response in chunks
    const stream = streamText(prompt);
    
    // Sending response in chunks
    res.setHeader('Content-Type', 'text/plain');  // Set content type for streaming
    stream.on('data', (chunk) => {
      res.write(chunk);  // Write each chunk to the response
    });

    // End the response when streaming is complete
    stream.on('end', () => {
      res.end();
    });

    // Handle any streaming errors
    stream.on('error', (error) => {
      console.error('Streaming error:', error);
      res.status(500).json({ error: 'Internal server error' });
    });
  } catch (error) {
    console.error('Error generating AI response:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};
