FROM node:24-alpine@sha256:a34ab6d7f6f4813f4d0c5469d74685604b962fbdbf5793a7bc7b4998ecb867c8 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ARG VITE_OIDC_AUTHORITY=http://hoocloak.localhost:8080/realms/development
ARG VITE_API_BASE_URL=http://api.localhost:5099
ENV VITE_OIDC_AUTHORITY="$VITE_OIDC_AUTHORITY"
ENV VITE_API_BASE_URL="$VITE_API_BASE_URL"
RUN npm run build && \
    node --input-type=module -e '\
      import { readFileSync, writeFileSync } from "node:fs"; \
      const config = readFileSync("nginx.conf", "utf8") \
        .replaceAll("__OIDC_ORIGIN__", new URL(process.env.VITE_OIDC_AUTHORITY).origin) \
        .replaceAll("__API_ORIGIN__", new URL(process.env.VITE_API_BASE_URL).origin); \
      writeFileSync("/tmp/default.conf", config);'

FROM nginxinc/nginx-unprivileged:alpine@sha256:18d67281256ded39ff65e010ae4f831be18f19356f83c60bc546492c7eb6dd23
COPY --from=build /tmp/default.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 5173
ENTRYPOINT ["nginx", "-g", "daemon off;"]
