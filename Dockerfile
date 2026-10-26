FROM node:24-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY server.js session_guard.js ./
RUN chmod 0644 package.json package-lock.json server.js session_guard.js
ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080
USER node
CMD ["node","server.js"]
