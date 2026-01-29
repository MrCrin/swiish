# Build Stage
FROM node:22-alpine as build
WORKDIR /app

# Install git to allow branch detection
RUN apk add --no-cache git

COPY package*.json ./
COPY tailwind.config.js ./
COPY postcss.config.js ./
COPY scripts/ scripts/
RUN npm install

COPY public/ public/
COPY src/ src/
COPY .git/ .git/

# Configure git to trust the directory (fixes dubious ownership in Docker)
RUN git config --global --add safe.directory /app

# Build the app (this triggers prebuild which runs capture-git-info.js)
RUN npm run build && rm -rf .git

# Production Stage
FROM node:22-alpine
WORKDIR /app

# Install fonts for SVG text rendering in preview images
RUN apk add --no-cache ttf-dejavu fontconfig

COPY --from=build /app/build ./build
COPY --from=build /app/src/active-branch.json ./active-branch.json
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
