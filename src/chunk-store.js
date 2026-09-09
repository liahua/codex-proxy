import { mkdir, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

function chunkFilename(index) {
  return `chunk-${String(index).padStart(6, "0")}.bin`;
}

export class ChunkRequestStore {
  constructor(baseDir, ttlMs) {
    this.baseDir = baseDir;
    this.ttlMs = ttlMs;
  }

  requestDir(requestId) {
    return join(this.baseDir, requestId);
  }

  metadataPath(requestId) {
    return join(this.requestDir(requestId), "metadata.json");
  }

  async ensureBaseDir() {
    await mkdir(this.baseDir, { recursive: true });
  }

  async purgeExpired() {
    await this.ensureBaseDir();
    const now = Date.now();
    for (const entry of await readdir(this.baseDir, { withFileTypes: true })) {
      if (!entry.isDirectory() || entry.name === "snapshots") {
        continue;
      }
      const dir = join(this.baseDir, entry.name);
      try {
        const info = await stat(dir);
        if (now - info.mtimeMs > this.ttlMs) {
          await rm(dir, { recursive: true, force: true });
        }
      } catch {
        // Ignore transient cleanup failures.
      }
    }
  }

  async createRequest(metadata) {
    await this.ensureBaseDir();
    await this.purgeExpired();
    const requestDir = this.requestDir(metadata.requestId);
    await mkdir(requestDir, { recursive: true });
    await writeFile(this.metadataPath(metadata.requestId), JSON.stringify(metadata, null, 2), "utf8");
  }

  async getRequest(requestId) {
    return JSON.parse(await readFile(this.metadataPath(requestId), "utf8"));
  }

  async writeChunk(requestId, index, content) {
    const file = join(this.requestDir(requestId), chunkFilename(index));
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, content);
  }

  async assemble(requestId) {
    const metadata = await this.getRequest(requestId);
    const buffers = [];
    for (let index = 0; index < metadata.chunkCount; index += 1) {
      const file = join(this.requestDir(requestId), chunkFilename(index));
      let chunk;
      try {
        chunk = await readFile(file);
      } catch (error) {
        if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
          throw new Error(`missing chunk ${index} for request ${requestId}`);
        }
        throw error;
      }
      buffers.push(chunk);
    }
    return { metadata, body: Buffer.concat(buffers) };
  }

  async remove(requestId) {
    await rm(this.requestDir(requestId), { recursive: true, force: true });
  }
}

/**
 * Holds the exact request bytes a client compressed against, so the next
 * request can ship as a zstd delta instead of the whole conversation.
 *
 * Two properties matter:
 *  - the stored bytes are byte-identical to what the client kept, so neither
 *    side has to agree on a JSON canonicalisation for the dictionary to match
 *  - retention is per conversation, so concurrent Codex sessions cannot evict
 *    each other's base and fall back to full uploads
 */
export class RelaySnapshotStore {
  /**
   * @param cipher optional { seal(buffer): string, open(string): buffer }.
   * Snapshots are whole request bodies; without a cipher the relay would keep
   * conversation content in plaintext on disk.
   *
   * Retention is deliberately three-layered: a TTL, a per-conversation depth,
   * and caps on both count and total bytes. Bytes matter most - a snapshot is
   * a whole request body, so a count-only cap says nothing about disk use.
   */
  constructor(
    baseDir,
    ttlMs,
    cipher = null,
    { maxSnapshots = 500, maxBytes = 2 * 1024 * 1024 * 1024, keepPerConversation = 5 } = {}
  ) {
    this.baseDir = join(baseDir, "snapshots");
    this.ttlMs = ttlMs;
    this.cipher = cipher;
    this.maxSnapshots = maxSnapshots;
    this.maxBytes = maxBytes;
    // More than one, because a client cannot have adopted the snapshot from a
    // response that is still streaming. Dropping the previous one immediately
    // would 409 the very next request it sends.
    this.keepPerConversation = Math.max(1, keepPerConversation);
    // Index of what is on disk, so pruning does not re-read every metadata
    // file on every request. Built once, then kept in step with writes.
    this.index = null;
  }

  snapshotDir(snapshotId) {
    return join(this.baseDir, snapshotId);
  }

  metadataPath(snapshotId) {
    return join(this.snapshotDir(snapshotId), "metadata.json");
  }

  bodyPath(snapshotId) {
    return join(this.snapshotDir(snapshotId), "body.bin");
  }

  async ensureBaseDir() {
    await mkdir(this.baseDir, { recursive: true });
  }

  /** Reads the index off disk once, on first use after a restart. */
  async loadIndex() {
    if (this.index) {
      return this.index;
    }
    await this.ensureBaseDir();
    this.index = new Map();
    for (const entry of await readdir(this.baseDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) {
        continue;
      }
      try {
        const metadata = JSON.parse(await readFile(this.metadataPath(entry.name), "utf8"));
        let storedBytes = metadata.storedBytes;
        if (typeof storedBytes !== "number") {
          storedBytes = (await stat(this.bodyPath(entry.name))).size;
        }
        this.index.set(entry.name, {
          snapshotId: entry.name,
          conversationKey: metadata.conversationKey || "",
          createdAt: metadata.createdAt || 0,
          storedBytes
        });
      } catch {
        // half-written or already removed
      }
    }
    return this.index;
  }

  /**
   * Applies all three retention limits. Runs when a snapshot is created, so
   * cleanup is lazy: an idle relay keeps expired snapshots until the next
   * request, bounded by the TTL rather than removed exactly at it.
   */
  async prune(keepSnapshotId) {
    const index = await this.loadIndex();
    const now = Date.now();
    const doomed = [];

    const live = [];
    for (const entry of index.values()) {
      if (entry.snapshotId !== keepSnapshotId && now - entry.createdAt > this.ttlMs) {
        doomed.push(entry);
        continue;
      }
      live.push(entry);
    }

    // Newest first, so "keep the newest N" falls out of the ordering.
    live.sort((left, right) => right.createdAt - left.createdAt);

    const perConversation = new Map();
    const survivors = [];
    for (const entry of live) {
      const key = entry.conversationKey || entry.snapshotId;
      const seen = perConversation.get(key) || 0;
      if (seen >= this.keepPerConversation && entry.snapshotId !== keepSnapshotId) {
        doomed.push(entry);
        continue;
      }
      perConversation.set(key, seen + 1);
      survivors.push(entry);
    }

    let bytes = 0;
    for (const [position, entry] of survivors.entries()) {
      bytes += entry.storedBytes;
      const overCount = position >= this.maxSnapshots;
      const overBytes = bytes > this.maxBytes && position > 0;
      if ((overCount || overBytes) && entry.snapshotId !== keepSnapshotId) {
        doomed.push(entry);
      }
    }

    for (const entry of doomed) {
      await this.remove(entry.snapshotId);
    }
    return doomed.length;
  }

  async createSnapshot(metadata, bodyBuffer) {
    await this.ensureBaseDir();
    const index = await this.loadIndex();
    const stored = this.cipher ? Buffer.from(this.cipher.seal(bodyBuffer), "utf8") : bodyBuffer;
    const record = { ...metadata, storedBytes: stored.length };

    const snapshotDir = this.snapshotDir(metadata.snapshotId);
    await mkdir(snapshotDir, { recursive: true });
    await writeFile(this.metadataPath(metadata.snapshotId), JSON.stringify(record, null, 2), "utf8");
    await writeFile(this.bodyPath(metadata.snapshotId), stored);

    index.set(metadata.snapshotId, {
      snapshotId: metadata.snapshotId,
      conversationKey: metadata.conversationKey || "",
      createdAt: metadata.createdAt || Date.now(),
      storedBytes: stored.length
    });
    await this.prune(metadata.snapshotId);
  }

  async hasSnapshot(snapshotId) {
    return (await this.loadIndex()).has(snapshotId);
  }

  async getSnapshot(snapshotId) {
    const [metadataRaw, storedBody] = await Promise.all([
      readFile(this.metadataPath(snapshotId), "utf8"),
      readFile(this.bodyPath(snapshotId))
    ]);
    return {
      metadata: JSON.parse(metadataRaw),
      body: this.cipher ? this.cipher.open(storedBody.toString("utf8")) : storedBody
    };
  }

  async stats() {
    const index = await this.loadIndex();
    let bytes = 0;
    const conversations = new Set();
    for (const entry of index.values()) {
      bytes += entry.storedBytes;
      conversations.add(entry.conversationKey || entry.snapshotId);
    }
    return { snapshots: index.size, conversations: conversations.size, bytes };
  }

  async remove(snapshotId) {
    await rm(this.snapshotDir(snapshotId), { recursive: true, force: true });
    this.index?.delete(snapshotId);
  }
}
