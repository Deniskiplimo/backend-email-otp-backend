class MaxConcurrencyThrottler {
    constructor({ maxConcurrentCalls }) {
        Object.defineProperty(this, "maxConcurrentCalls", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "activeCallCount", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "callQueue", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this.maxConcurrentCalls = maxConcurrentCalls;
        this.activeCallCount = 0;
        this.callQueue = [];
    }
    async run(fn) {
        return new Promise((resolve, reject) => {
            const tryExecute = async () => {
                if (this.activeCallCount >= this.maxConcurrentCalls)
                    return;
                // mark as active and remove from queue:
                this.activeCallCount++;
                const idx = this.callQueue.indexOf(tryExecute);
                if (idx !== -1)
                    this.callQueue.splice(idx, 1);
                try {
                    resolve(await fn());
                }
                catch (error) {
                    reject(error);
                }
                finally {
                    this.activeCallCount--;
                    if (this.callQueue.length > 0) {
                        this.callQueue[0]();
                    }
                }
            };
            this.callQueue.push(tryExecute);
            if (this.activeCallCount < this.maxConcurrentCalls) {
                tryExecute();
            }
        });
    }
}
/**
 * The `throttleMaxConcurrency` strategy limits the number of parallel API calls.
 */
export function throttleMaxConcurrency({ maxConcurrentCalls, }) {
    const throttler = new MaxConcurrencyThrottler({ maxConcurrentCalls });
    return (fn) => throttler.run(fn);
}
