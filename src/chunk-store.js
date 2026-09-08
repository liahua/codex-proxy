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
   */
  constructor(baseDir, ttlMs, cipher = null, { maxSnapshots = 200, keepPerConversation = 2 } = {}) {
    this.baseDir = join(baseDir, "snapshots");
    this.ttlMs = ttlMs;
    this.cipher = cipher;
    this.maxSnapshots = maxSnapshots;
    // More than one, because a client cannot have adopted the snapshot from a
    // response that is still streaming. Dropping the previous one immediately
    // would 409 the very next request it sends.
    this.keepPerConversation = Math.max(1, keepPerConversation);
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

  async listSnapshots() {
    await this.ensureBaseDir();
    const entries = await readdir(this.baseDir, { withFileTypes: true });
    const snapshots = [];
    for (const entry of entries) {
      if (!entry.isDirectory()) {
        continue;
      }
      try {
        const metadata = JSON.parse(await readFile(this.metadataPath(entry.name), "utf8"));
        snapshots.push(metadata);
      } catch {
        // half-written or already removed
      }
    }
    return snapshots;
  }

  async purgeExpired() {
    const now = Date.now();
    const snapshots = await this.listSnapshots();
    const live = [];
    for (const snapshot of snapshots) {
      if (now - (snapshot.createdAt || 0) > this.ttlMs) {
        await this.remove(snapshot.snapshotId);
        continue;
      }
      live.push(snapshot);
    }
    return live;
  }

  /**
   * Keeps the newest snapshot per conversation, then caps the total count by
   * dropping the least recently created conversations.
   */
  async prune(keepConversationKey, keepSnapshotId) {
    const live = await this.purgeExpired();

    const byConversation = new Map();
    for (const snapshot of live) {
      const key = snapshot.conversationKey || snapshot.snapshotId;
      if (!byConversation.has(key)) {
        byConversation.set(key, []);
      }
      byConversation.get(key).push(snapshot);
    }

    const survivors = [];
    for (const [, snapshots] of byConversation) {
      snapshots.sort((left, right) => (right.createdAt || 0) - (left.createdAt || 0));
      for (const [index, snapshot] of snapshots.entries()) {
        if (index < this.keepPerConversation || snapshot.snapshotId === keepSnapshotId) {
          survivors.push(snapshot);
        } else {
          await this.remove(snapshot.snapshotId);
        }
      }
    }

    // Then bound the whole store, oldest conversations first.
    survivors.sort((left, right) => (right.createdAt || 0) - (left.createdAt || 0));
    for (const snapshot of survivors.slice(this.maxSnapshots)) {
      if (snapshot.conversationKey === keepConversationKey || snapshot.snapshotId === keepSnapshotId) {
        continue;
      }
      await this.remove(snapshot.snapshotId);
    }
  }

  async createSnapshot(metadata, bodyBuffer) {
    await this.ensureBaseDir();
    const snapshotDir = this.snapshotDir(metadata.snapshotId);
    await mkdir(snapshotDir, { recursive: true });
    await writeFile(this.metadataPath(metadata.snapshotId), JSON.stringify(metadata, null, 2), "utf8");
    await writeFile(
      this.bodyPath(metadata.snapshotId),
      this.cipher ? Buffer.from(this.cipher.seal(bodyBuffer), "utf8") : bodyBuffer
    );
    await this.prune(metadata.conversationKey, metadata.snapshotId);
  }

  async hasSnapshot(snapshotId) {
    try {
      await stat(this.metadataPath(snapshotId));
      return true;
    } catch {
      return false;
    }
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

  async remove(snapshotId) {
    await rm(this.snapshotDir(snapshotId), { recursive: true, force: true });
  }
}
