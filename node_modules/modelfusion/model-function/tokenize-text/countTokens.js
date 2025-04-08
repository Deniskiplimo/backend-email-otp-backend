/**
 * Count the number of tokens in the given text.
 */
export async function countTokens(tokenizer, text) {
    return (await tokenizer.tokenize(text)).length;
}
