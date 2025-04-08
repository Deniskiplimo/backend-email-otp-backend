export class FunctionEventSource {
    constructor({ observers, errorHandler, }) {
        Object.defineProperty(this, "observers", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "errorHandler", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this.observers = observers;
        this.errorHandler = errorHandler ?? ((error) => console.error(error));
    }
    notify(event) {
        for (const observer of this.observers) {
            try {
                observer.onFunctionEvent(event);
            }
            catch (error) {
                this.errorHandler(error);
            }
        }
    }
}
