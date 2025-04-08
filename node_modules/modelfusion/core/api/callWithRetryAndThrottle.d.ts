import { RetryFunction } from "./RetryFunction.js";
import { ThrottleFunction } from "./ThrottleFunction.js";
export declare const callWithRetryAndThrottle: <OUTPUT>({ retry, throttle, call, }: {
    retry?: RetryFunction | undefined;
    throttle?: ThrottleFunction | undefined;
    call: () => PromiseLike<OUTPUT>;
}) => Promise<OUTPUT>;
