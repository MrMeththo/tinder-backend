FROM node:22-alpine

WORKDIR /app

COPY package*.json ./
COPY prisma ./prisma

RUN npm install

COPY . .

RUN npx prisma generate

ENV PORT=3000
EXPOSE 3000

CMD ["npm", "start"]
