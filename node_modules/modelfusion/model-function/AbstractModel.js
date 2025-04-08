export class AbstractModel {
    constructor({ settings }) {
        Object.defineProperty(this, "settings", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this.settings = settings;
    }
    // implemented as a separate accessor to remove all other properties from the model
    get modelInformation() {
        return {
            provider: this.provider,
            modelName: this.modelName,
        };
    }
}
