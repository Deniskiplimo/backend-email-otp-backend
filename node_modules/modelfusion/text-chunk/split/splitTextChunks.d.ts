import { TextChunk } from "../TextChunk.js";
import { SplitFunction } from "./SplitFunction.js";
export declare function splitTextChunks<CHUNK extends TextChunk>(splitFunction: SplitFunction, inputs: CHUNK[]): Promise<CHUNK[]>;
export declare function splitTextChunk<CHUNK extends TextChunk>(splitFunction: SplitFunction, input: CHUNK): Promise<CHUNK[]>;
