import { ParsedEvent } from "eventsource-parser";
export declare function parseEventSourceStream({ stream, }: {
    stream: ReadableStream<Uint8Array>;
}): Promise<AsyncIterable<ParsedEvent>>;
