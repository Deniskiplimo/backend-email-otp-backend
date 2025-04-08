/**
 * Formats a basic text prompt as an Automatic1111 prompt.
 */
export function mapBasicPromptToAutomatic1111Format() {
    return {
        format: (description) => ({ prompt: description }),
    };
}
