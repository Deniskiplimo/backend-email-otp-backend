/**
 * The `retryNever` strategy never retries a failed API call.
 */
export declare const retryNever: () => <OUTPUT>(f: () => PromiseLike<OUTPUT>) => Promise<OUTPUT>;
