FROM node:20-alpine

WORKDIR /app

# Copy dependency specifications
COPY package*.json ./

# Install production dependencies
RUN npm ci --only=production

# Copy source code
COPY . .

# Expose HTTP port
EXPOSE 3000

ENV NODE_ENV=production
ENV WEB_PORT=3000

CMD ["node", "src/server.js"]
