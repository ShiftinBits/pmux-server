/**
 * Mock WebSocket for testing the Durable Object's Hibernation API handlers.
 *
 * Tracks sent messages and supports serializeAttachment/deserializeAttachment
 * as required by the Cloudflare Workers Hibernation API.
 */

export class MockWebSocket {
  /** Messages sent via ws.send(), stored as parsed objects. */
  sent: unknown[] = [];

  /** Whether ws.close() was called. */
  closed = false;

  /** Close code if ws.close() was called. */
  closeCode?: number;

  /** Close reason if ws.close() was called. */
  closeReason?: string;

  private attachment: unknown = null;

  send(message: string): void {
    this.sent.push(JSON.parse(message));
  }

  close(code?: number, reason?: string): void {
    this.closed = true;
    this.closeCode = code;
    this.closeReason = reason;
  }

  serializeAttachment(value: unknown): void {
    this.attachment = value;
  }

  deserializeAttachment(): unknown {
    return this.attachment;
  }

  /** Get the last sent message as a typed object. */
  lastMessage<T = Record<string, unknown>>(): T | undefined {
    return this.sent[this.sent.length - 1] as T | undefined;
  }

  /** Get all sent messages of a given type. */
  messagesOfType(type: string): Record<string, unknown>[] {
    return this.sent.filter(
      (m) => typeof m === 'object' && m !== null && (m as Record<string, unknown>)['type'] === type
    ) as Record<string, unknown>[];
  }
}
