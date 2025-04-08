import { convertReadableStreamToAsyncIterable } from "./convertReadableStreamToAsyncIterable.js";
import { EventSourceParserStream } from "./EventSourceParserStream.js";
export async function parseEventSourceStream({ stream, }) {
    const eventStream = stream
        .pipeThrough(new TextDecoderStream())
        .pipeThrough(new EventSourceParserStream());
    return convertReadableStreamToAsyncIterable(eventStream);
}
