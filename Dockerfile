FROM node:20-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY --chown=node:node . .
USER node
EXPOSE 3000
CMD ["sh", "-c", "node setup.js && node server.js"]
