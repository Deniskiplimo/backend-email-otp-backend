/**
 * Calculates the cosine similarity between two vectors. They must have the same length.
 *
 * @param a The first vector.
 * @param b The second vector.
 *
 * @returns The cosine similarity between the two vectors.
 *
 * @see https://en.wikipedia.org/wiki/Cosine_similarity
 */
export function cosineSimilarity(a, b) {
    if (a.length !== b.length) {
        throw new Error(`Vectors must have the same length (a: ${a.length}, b: ${b.length})`);
    }
    return dotProduct(a, b) / (magnitude(a) * magnitude(b));
}
function dotProduct(a, b) {
    return a.reduce((acc, val, i) => acc + val * b[i], 0);
}
function magnitude(a) {
    return Math.sqrt(dotProduct(a, a));
}
