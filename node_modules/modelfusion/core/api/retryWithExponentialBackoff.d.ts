import { RetryFunction } from "./RetryFunction.js";
/**
 * The `retryWithExponentialBackoff` strategy retries a failed API call with an exponential backoff.
 * You can configure the maximum number of tries, the initial delay, and the backoff factor.
 */
export declare const retryWithExponentialBackoff: ({ maxTries, initialDelayInMs, backoffFactor, }?: {
    maxTries?: number | undefined;
    initialDelayInMs?: number | undefined;
    backoffFactor?: number | undefined;
}) => RetryFunction;
