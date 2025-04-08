export function startDurationMeasurement() {
    // certain environments may not have the performance API:
    return globalThis.performance != null
        ? new PerformanceNowDurationMeasurement()
        : new DateDurationMeasurement();
}
class PerformanceNowDurationMeasurement {
    constructor() {
        Object.defineProperty(this, "startTime", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: globalThis.performance.now()
        });
    }
    get startEpochSeconds() {
        return Math.floor((globalThis.performance.timeOrigin + this.startTime) / 1000);
    }
    get startDate() {
        return new Date(this.startEpochSeconds * 1000);
    }
    get durationInMs() {
        return Math.ceil(globalThis.performance.now() - this.startTime);
    }
}
class DateDurationMeasurement {
    constructor() {
        Object.defineProperty(this, "startTime", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: Date.now()
        });
    }
    get startEpochSeconds() {
        return Math.floor(this.startTime / 1000);
    }
    get startDate() {
        return new Date(this.startTime);
    }
    get durationInMs() {
        return Date.now() - this.startTime;
    }
}
