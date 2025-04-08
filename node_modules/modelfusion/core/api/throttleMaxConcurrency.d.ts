import { ThrottleFunction } from "./ThrottleFunction.js";
/**
 * The `throttleMaxConcurrency` strategy limits the number of parallel API calls.
 */
export declare function throttleMaxConcurrency({ maxConcurrentCalls, }: {
    maxConcurrentCalls: number;
}): ThrottleFunction;
