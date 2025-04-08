import { ErrorHandler } from "../util/ErrorHandler.js";
import { FunctionEvent } from "./FunctionEvent.js";
import { FunctionObserver } from "./FunctionObserver.js";
export declare class FunctionEventSource {
    readonly observers: FunctionObserver[];
    readonly errorHandler: ErrorHandler;
    constructor({ observers, errorHandler, }: {
        observers: FunctionObserver[];
        errorHandler?: ErrorHandler;
    });
    notify(event: FunctionEvent): void;
}
