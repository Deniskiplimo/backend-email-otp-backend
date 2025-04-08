import { FunctionOptions } from "../core/FunctionOptions.js";
import { Retriever } from "./Retriever.js";
export declare function retrieve<OBJECT, QUERY>(retriever: Retriever<OBJECT, QUERY>, query: QUERY, options?: FunctionOptions): Promise<OBJECT[]>;
