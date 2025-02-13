const axios = require('axios');
const payload = {
    prompt: "Provide only the Python code for a recursive function named factorial. Do not include any explanations.",
    n_predict: 100,
    stop: ["```"],  // Helps stop after code is generated
    temperature: 0.5  // Ensures less randomness
};
(async () => {
    try {
        const res = await axios.post("http://localhost:4000/completion", 
            { prompt: "Generate a Python function to calculate factorial." }, 
            { timeout: 60000 });

        console.log("✅ AI Response:", res.data);
    } catch (error) {
        console.error("❌ AI Model Error:", error.message);
    }
})();
