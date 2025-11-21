# Usa una imagen oficial de Node.js
FROM node:20-alpine

# Crea el directorio de trabajo dentro del contenedor
WORKDIR /usr/src/app

# Copia package.json y package-lock.json (si existe)
COPY package*.json ./

# Instala dependencias
RUN npm install

# Copia el resto del código de la app
COPY . .

# Expone el puerto en el que correrá la app
EXPOSE 3000

# Comando por defecto para iniciar la app
CMD ["npm", "start"]