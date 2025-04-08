import { FullTokenizer } from "../../model-function/tokenize-text/Tokenizer.js";
import { SplitFunction } from "./SplitFunction.js";
/**
 * Splits text recursively until the resulting chunks are smaller than the `maxCharactersPerChunk`.
 * The text is recursively split in the middle, so that all chunks are roughtly the same size.
 */
export declare const splitAtCharacter: ({ maxCharactersPerChunk, }: {
    maxCharactersPerChunk: number;
}) => SplitFunction;
/**
 * Splits text recursively until the resulting chunks are smaller than the `maxTokensPerChunk`,
 * while respecting the token boundaries.
 * The text is recursively split in the middle, so that all chunks are roughtly the same size.
 */
export declare const splitAtToken: ({ tokenizer, maxTokensPerChunk, }: {
    tokenizer: FullTokenizer;
    maxTokensPerChunk: number;
}) => SplitFunction;
