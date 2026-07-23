FROM node:24-alpine@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd AS build
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

FROM nginxinc/nginx-unprivileged:alpine@sha256:6320020c7da8714feab524e02c08c5a1958675c4e68700e93a2fd8970b065786
COPY --from=build /tmp/default.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 5173
ENTRYPOINT ["nginx", "-g", "daemon off;"]
