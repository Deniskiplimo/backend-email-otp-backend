export async function splitTextChunks(splitFunction, inputs) {
    const pageChunks = await Promise.all(inputs.map((input) => splitTextChunk(splitFunction, input)));
    return pageChunks.flat();
}
export async function splitTextChunk(splitFunction, input) {
    const parts = await splitFunction(input);
    return parts.map((text) => ({
        ...input,
        text,
    }));
}
