import { SafeResult } from "./SafeResult.js";
export declare const runSafe: <OUTPUT>(f: () => PromiseLike<OUTPUT>) => Promise<SafeResult<OUTPUT>>;
