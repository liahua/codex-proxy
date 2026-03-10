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
