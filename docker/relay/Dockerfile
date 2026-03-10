FROM node:22-bookworm-slim

WORKDIR /app

COPY package.json /app/package.json
COPY package-lock.json /app/package-lock.json
COPY src /app/src

RUN npm ci --omit=dev
RUN mkdir -p /app/data/chunked-requests

EXPOSE 8787

CMD ["node", "src/server.js"]
