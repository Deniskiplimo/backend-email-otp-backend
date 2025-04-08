/**
 * The `retryNever` strategy never retries a failed API call.
 */
export const retryNever = () => async (f) => f();
