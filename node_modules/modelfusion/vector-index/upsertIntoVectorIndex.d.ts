import { FunctionOptions } from "../core/FunctionOptions.js";
import { EmbeddingModel, EmbeddingModelSettings } from "../model-function/embed/EmbeddingModel.js";
import { VectorIndex } from "./VectorIndex.js";
export declare function upsertIntoVectorIndex<VALUE, OBJECT>({ vectorIndex, embeddingModel, generateId, objects, getValueToEmbed, getId, }: {
    vectorIndex: VectorIndex<OBJECT, unknown, unknown>;
    embeddingModel: EmbeddingModel<VALUE, EmbeddingModelSettings>;
    generateId?: () => string;
    objects: OBJECT[];
    getValueToEmbed: (object: OBJECT, index: number) => VALUE;
    getId?: (object: OBJECT, index: number) => string | undefined;
}, options?: FunctionOptions): Promise<void>;
