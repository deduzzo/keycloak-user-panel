FROM node:22-alpine

WORKDIR /app

# Installa dipendenze separatamente per migliorare caching layer
COPY package*.json ./
RUN npm install --omit=dev

# Copia il resto del codice
COPY . .

EXPOSE 3000

# L'app risponde su tutte le interfacce; ASP-WS proxa /apps/<id>/
CMD ["node", "server.js"]
