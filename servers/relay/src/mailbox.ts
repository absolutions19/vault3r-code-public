/**
 * Per-topic store-and-forward mailbox with a bounded size and TTL. Used when a
 * peer publishes to a topic that currently has no live subscriber (the other
 * peer is offline / the phone is asleep). Bounded in both dimensions so a topic
 * cannot be used to exhaust memory; oldest messages are evicted first.
 */

export interface MailboxItem {
  id: string;
  payload: string;
  tag: string;
  expiry: number;
}

export interface MailboxOptions {
  ttlMs: number;
  maxPerTopic: number;
  maxTotal: number;
}

export class TopicMailbox {
  private readonly topics = new Map<string, MailboxItem[]>();
  private total = 0;

  constructor(private readonly opts: MailboxOptions) {}

  enqueue(topic: string, item: Omit<MailboxItem, "expiry">, now: number): boolean {
    this.prune(now);
    if (this.total >= this.opts.maxTotal) return false;
    const list = this.topics.get(topic) ?? [];
    list.push({ ...item, expiry: now + this.opts.ttlMs });
    while (list.length > this.opts.maxPerTopic) {
      list.shift();
      this.total--;
    }
    this.topics.set(topic, list);
    this.total++;
    return true;
  }

  /** Return and remove all unexpired items for a topic (delivery on subscribe). */
  drain(topic: string, now: number): MailboxItem[] {
    const list = this.topics.get(topic);
    if (!list) return [];
    const live = list.filter((i) => i.expiry > now);
    this.total -= list.length;
    this.topics.delete(topic);
    return live;
  }

  prune(now: number): void {
    for (const [topic, list] of this.topics) {
      const live = list.filter((i) => i.expiry > now);
      this.total -= list.length - live.length;
      if (live.length === 0) this.topics.delete(topic);
      else this.topics.set(topic, live);
    }
  }

  size(): number {
    return this.total;
  }
}
