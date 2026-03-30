FROM node:24-alpine AS builder
RUN apk add --no-cache python3 make g++
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev

FROM node:24-alpine
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY server.js ./
COPY public/ ./public/
RUN mkdir -p /data
EXPOSE 3000
CMD ["node", "server.js"]
