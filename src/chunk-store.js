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
      if (!entry.isDirectory()) {
        continue;
      }
      if (entry.name === "snapshots") {
        continue;
      }
      if (entry.name === "response-snapshots") {
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
    const raw = await readFile(this.metadataPath(requestId), "utf8");
    return JSON.parse(raw);
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
    return {
      metadata,
      body: Buffer.concat(buffers)
    };
  }

  async remove(requestId) {
    await rm(this.requestDir(requestId), { recursive: true, force: true });
  }
}

export class RelaySnapshotStore {
  /**
   * @param cipher optional { seal(text): text, open(text): text }. Snapshots hold
   * full request bodies, so without one the relay would keep conversation
   * content in plaintext on disk while advertising encrypted transport.
   */
  constructor(baseDir, ttlMs, cipher = null) {
    this.baseDir = join(baseDir, "snapshots");
    this.ttlMs = ttlMs;
    this.cipher = cipher;
  }

  snapshotDir(snapshotId) {
    return join(this.baseDir, snapshotId);
  }

  metadataPath(snapshotId) {
    return join(this.snapshotDir(snapshotId), "metadata.json");
  }

  bodyPath(snapshotId) {
    return join(this.snapshotDir(snapshotId), "body.json");
  }

  async ensureBaseDir() {
    await mkdir(this.baseDir, { recursive: true });
  }

  async purgeExpired() {
    await this.ensureBaseDir();
    const now = Date.now();
    for (const entry of await readdir(this.baseDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) {
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

  async createSnapshot(metadata, bodyJson) {
    await this.ensureBaseDir();
    await this.purgeExpired();
    const snapshotDir = this.snapshotDir(metadata.snapshotId);
    await mkdir(snapshotDir, { recursive: true });
    await writeFile(this.metadataPath(metadata.snapshotId), JSON.stringify(metadata, null, 2), "utf8");
    await writeFile(
      this.bodyPath(metadata.snapshotId),
      this.cipher ? this.cipher.seal(bodyJson) : bodyJson,
      "utf8"
    );
  }

  async getSnapshot(snapshotId) {
    const [metadataRaw, storedBody] = await Promise.all([
      readFile(this.metadataPath(snapshotId), "utf8"),
      readFile(this.bodyPath(snapshotId), "utf8")
    ]);
    return {
      metadata: JSON.parse(metadataRaw),
      bodyJson: this.cipher ? this.cipher.open(storedBody) : storedBody
    };
  }
}

export class RelayResponseSnapshotStore {
  /** Holds upstream response text; see RelaySnapshotStore for why cipher matters. */
  constructor(baseDir, ttlMs, cipher = null) {
    this.baseDir = join(baseDir, "response-snapshots");
    this.ttlMs = ttlMs;
    this.cipher = cipher;
  }

  snapshotDir(snapshotId) {
    return join(this.baseDir, snapshotId);
  }

  metadataPath(snapshotId) {
    return join(this.snapshotDir(snapshotId), "metadata.json");
  }

  textsPath(snapshotId) {
    return join(this.snapshotDir(snapshotId), "texts.json");
  }

  async ensureBaseDir() {
    await mkdir(this.baseDir, { recursive: true });
  }

  async purgeExpired() {
    await this.ensureBaseDir();
    const now = Date.now();
    for (const entry of await readdir(this.baseDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) {
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

  async createSnapshot(metadata, texts) {
    await this.ensureBaseDir();
    await this.purgeExpired();
    const snapshotDir = this.snapshotDir(metadata.snapshotId);
    await mkdir(snapshotDir, { recursive: true });
    await writeFile(this.metadataPath(metadata.snapshotId), JSON.stringify(metadata, null, 2), "utf8");
    const textsJson = JSON.stringify(texts, null, 2);
    await writeFile(
      this.textsPath(metadata.snapshotId),
      this.cipher ? this.cipher.seal(textsJson) : textsJson,
      "utf8"
    );
  }

  async getText(snapshotId, textSha256) {
    const stored = await readFile(this.textsPath(snapshotId), "utf8");
    const texts = JSON.parse(this.cipher ? this.cipher.open(stored) : stored);
    const match = Array.isArray(texts) ? texts.find((item) => item?.sha256 === textSha256) : null;
    if (!match || typeof match.text !== "string") {
      throw new Error("response ref text unavailable");
    }
    return match.text;
  }
}
