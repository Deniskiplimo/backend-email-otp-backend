import { OpenAIChatMessage } from "./OpenAIChatMessage.js";
import { OpenAIChatModelType } from "./OpenAIChatModel.js";
/**
 * Prompt tokens that are included automatically for every full
 * chat prompt (several messages) that is sent to OpenAI.
 */
export declare const OPENAI_CHAT_PROMPT_BASE_TOKEN_COUNT = 2;
/**
 * Prompt tokens that are included automatically for every
 * message that is sent to OpenAI.
 */
export declare const OPENAI_CHAT_MESSAGE_BASE_TOKEN_COUNT = 5;
export declare function countOpenAIChatMessageTokens({ message, model, }: {
    message: OpenAIChatMessage;
    model: OpenAIChatModelType;
}): Promise<number>;
export declare function countOpenAIChatPromptTokens({ messages, model, }: {
    messages: OpenAIChatMessage[];
    model: OpenAIChatModelType;
}): Promise<number>;
