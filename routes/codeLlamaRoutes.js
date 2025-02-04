const express = require("express");
const { 
    handleCodeLlamaRequest,
    handleExplainCodeRequest,
    handleDebugCodeRequest,
    handleRefactorCodeRequest,
    handleConvertCodeLanguageRequest,
    handleValidateCodeSyntaxRequest
} = require("../controllers/codeLlamaController");

const router = express.Router();

// Route for code generation
router.post("/generate", handleCodeLlamaRequest);

// Route for explaining code
router.post("/explain", handleExplainCodeRequest);

// Route for debugging code
router.post("/debug", handleDebugCodeRequest);

// Route for refactoring code
router.post("/refactor", handleRefactorCodeRequest);

// Route for converting code from one language to another
router.post("/convert", handleConvertCodeLanguageRequest);

// Route for validating code syntax
router.post("/validate", handleValidateCodeSyntaxRequest);

module.exports = router;
