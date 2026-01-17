# Build Stage
FROM node:18-alpine as build
WORKDIR /app

# Accept git branch as build argument (pass with --build-arg GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD))
ARG GIT_BRANCH=main

COPY package*.json ./
COPY tailwind.config.js ./
COPY postcss.config.js ./
COPY scripts/ scripts/
RUN npm install

COPY public/ public/
COPY src/ src/

# Create version.json with the branch info (since .git is not available in Docker)
RUN echo "{\"branch\": \"${GIT_BRANCH}\", \"capturedAt\": \"$(date -Iseconds)\"}" > src/version.json

RUN npm run build

# Production Stage
FROM node:18-alpine
WORKDIR /app
COPY --from=build /app/build ./build
COPY package*.json ./
RUN npm install --production
COPY server.js .
COPY database.json .
COPY migrations/ ./migrations/

# Create dirs for volumes
RUN mkdir data
RUN mkdir uploads

EXPOSE 3000
CMD ["node", "server.js"]
