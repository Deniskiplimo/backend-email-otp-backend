export declare function startDurationMeasurement(): DurationMeasurement;
export interface DurationMeasurement {
    startEpochSeconds: number;
    startDate: Date;
    durationInMs: number;
}
