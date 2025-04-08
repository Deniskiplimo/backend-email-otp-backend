import { Run } from "./Run";
/**
 * Returns the run stored in an AsyncLocalStorage if running in Node.js. It can be set with `withRun()`.
 */
export declare function getRun(run?: Run): Promise<Run | undefined>;
/**
 * Stores the run in an AsyncLocalStorage if running in Node.js. It can be retrieved with `getRun()`.
 */
export declare function withRun(run: Run, callback: (run: Run) => PromiseLike<void>): Promise<void>;
