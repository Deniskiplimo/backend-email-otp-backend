// ✅ Unified MODELS object (remove duplicates above)
const MODELS = {
  // Existing Models
  tinyLlama: {
    name: "TinyLlama-1.1B-Chat",
    url: "https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
    filename: "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
  },
  mistral: {
    name: "Mistral-7B-Instruct",
    url: "https://huggingface.co/mistralai/Mistral-7B-Instruct-v0.1-GGUF/resolve/main/mistral-7b-instruct-v0.1.Q4_K_M.gguf",
    filename: "mistral-7b-instruct-v0.1.Q4_K_M.gguf",
  },
  llama3: {
    name: "Llama-3-8B",
    url: "https://huggingface.co/meta-llama/Meta-Llama-3-8B-GGUF/resolve/main/meta-llama-3-8b.Q4_K_M.gguf",
    filename: "meta-llama-3-8b.Q4_K_M.gguf",
  },
  codeLlama: {
    name: "CodeLlama-7B",
    url: "https://huggingface.co/TheBloke/CodeLlama-7B-GGUF/resolve/main/codellama-7b.Q4_K_M.gguf",
    filename: "codellama-7b.Q4_K_M.gguf",
  },
  llama2_7b: {
    name: "Llama-2-7B",
    url: "https://huggingface.co/TheBloke/Llama-2-7B-GGUF/resolve/main/llama-2-7b.Q4_K_M.gguf",
    filename: "llama-2-7b.Q4_K_M.gguf",
  },
  llama2_13b: {
    name: "Llama-2-13B",
    url: "https://huggingface.co/TheBloke/Llama-2-13B-GGUF/resolve/main/llama-2-13b.Q4_K_M.gguf",
    filename: "llama-2-13b.Q4_K_M.gguf",
  },
  llama2_70b: {
    name: "Llama-2-70B",
    url: "https://huggingface.co/TheBloke/Llama-2-70B-GGUF/resolve/main/llama-2-70b.Q4_K_M.gguf",
    filename: "llama-2-70b.Q4_K_M.gguf",
  },

  // Media Generation Models
  stableDiffusionXL: {
    name: "Stable Diffusion XL",
    url: "https://huggingface.co/stabilityai/stable-diffusion-xl-base-1.0",
    filename: "stable-diffusion-xl-base-1.0",
  },
  deepFaceLab: {
    name: "DeepFaceLab",
    url: "https://github.com/iperov/DeepFaceLab",
    filename: "DeepFaceLab",
  },
  barkTTS: {
    name: "Bark (Text-to-Speech)",
    url: "https://github.com/suno-ai/bark",
    filename: "bark-tts",
  },

  // Automation / AI Workers
  whisper: {
    name: "Whisper (Speech Recognition)",
    url: "https://huggingface.co/openai/whisper-large-v3",
    filename: "whisper-large-v3",
  },
  autoGPT: {
    name: "AutoGPT",
    url: "https://github.com/Torantulino/Auto-GPT",
    filename: "AutoGPT",
  },
  babyAGI: {
    name: "BabyAGI",
    url: "https://github.com/yoheinakajima/babyagi",
    filename: "BabyAGI",
  },

  // Cybersecurity Models
  malConv: {
    name: "MalConv (Malware Detection)",
    url: "https://arxiv.org/abs/1710.09435",
    filename: "MalConv",
  },
  secBERT: {
    name: "SecBERT (Cybersecurity NLP)",
    url: "https://huggingface.co/tner/bert-base-cybersecurity-ner",
    filename: "SecBERT",
  },
  yara: {
    name: "YARA (Threat Detection)",
    url: "https://github.com/VirusTotal/yara",
    filename: "YARA",
  },

  // Robotics Models
  rosAI: {
    name: "ROS AI (Robot Operating System)",
    url: "https://www.ros.org/",
    filename: "ros-ai",
  },
  rt1: {
    name: "RT-1 (Google Robotics)",
    url: "https://robotics-transformer1.github.io/",
    filename: "rt1-robotics",
  },
  controlNet: {
    name: "ControlNet (AI for Robotics)",
    url: "https://github.com/lllyasviel/ControlNet",
    filename: "ControlNet",
  },
};

module.exports = MODELS;
