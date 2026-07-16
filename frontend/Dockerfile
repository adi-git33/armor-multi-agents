# Build stage — bake the backend origin into the Vite bundle.
# For docker-compose the default is right: the BROWSER talks to the
# backend through the host-mapped port (localhost:8000), not the
# container network.
FROM node:22-alpine AS build

ARG VITE_BACKEND_ORIGIN=http://localhost:8000
ENV VITE_BACKEND_ORIGIN=${VITE_BACKEND_ORIGIN}

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# Serve stage
FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
