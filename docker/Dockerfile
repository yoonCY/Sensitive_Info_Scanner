FROM node:20-bookworm-slim

WORKDIR /app

# better-sqlite3 빌드 대비 기본 툴
RUN apt-get update \
  ; apt-get install -y --no-install-recommends python3 make g++ \
  ; rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm install

COPY tsconfig.json ./
COPY src ./src
COPY frontend ./frontend
COPY architecture.md ./architecture.md
COPY README.md ./README.md

RUN npm run build

CMD ["npm", "run", "web"]