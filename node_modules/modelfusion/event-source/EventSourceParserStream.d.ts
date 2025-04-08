import { ParsedEvent } from "eventsource-parser";
/**
 * A TransformStream that ingests a stream of strings and produces a stream of ParsedEvents.
 *
 * @example
 * ```
 * const eventStream =
 *   response.body
 *     .pipeThrough(new TextDecoderStream())
 *     .pipeThrough(new EventSourceParserStream())
 * ```
 */
export declare class EventSourceParserStream extends TransformStream<string, ParsedEvent> {
    constructor();
}
