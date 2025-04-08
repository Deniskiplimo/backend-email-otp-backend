/**
 * Splits text on a separator string.
 */
export function splitOnSeparator({ separator, }) {
    return async ({ text }) => text.split(separator);
}
