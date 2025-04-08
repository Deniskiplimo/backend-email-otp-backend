import { FunctionOptions } from "../core/FunctionOptions.js";
import { EmbeddingModel, EmbeddingModelSettings } from "../model-function/embed/EmbeddingModel.js";
import { Retriever } from "../retriever/Retriever.js";
import { VectorIndex } from "./VectorIndex.js";
export interface VectorIndexRetrieverSettings<FILTER> {
    maxResults?: number;
    similarityThreshold?: number;
    filter?: FILTER;
}
export declare class VectorIndexRetriever<OBJECT, VALUE, INDEX, FILTER> implements Retriever<OBJECT, VALUE> {
    private readonly vectorIndex;
    private readonly embeddingModel;
    private readonly settings;
    constructor({ vectorIndex, embeddingModel, maxResults, similarityThreshold, filter, }: {
        vectorIndex: VectorIndex<OBJECT, INDEX, FILTER>;
        embeddingModel: EmbeddingModel<VALUE, EmbeddingModelSettings>;
    } & VectorIndexRetrieverSettings<FILTER>);
    retrieve(query: VALUE, options?: FunctionOptions): Promise<OBJECT[]>;
    withSettings(additionalSettings: Partial<VectorIndexRetrieverSettings<FILTER>>): this;
}
