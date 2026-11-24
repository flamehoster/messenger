FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY server ./server
COPY public ./public
RUN mkdir -p /data && chown node:node /data
USER node
ENV NODE_ENV=production HOST=0.0.0.0 PORT=8080 DATA_DIR=/data TRUST_PROXY=1 HSTS=1
EXPOSE 8080
VOLUME ["/data"]
CMD ["node", "server/server.js"]
