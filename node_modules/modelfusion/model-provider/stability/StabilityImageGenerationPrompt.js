/**
 * Formats a basic text prompt as a Stability prompt.
 */
export function mapBasicPromptToStabilityFormat() {
    return {
        format: (description) => [{ text: description }],
    };
}
