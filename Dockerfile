FROM node:24-alpine AS login
WORKDIR /src/ui/login
COPY ui/login/package.json ui/login/package-lock.json ./
RUN npm ci
COPY ui/login/ ./
RUN npm run build

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY --from=login /src/internal/idp/ui/dist ./internal/idp/ui/dist
RUN CGO_ENABLED=0 go build -tags no_otel -trimpath -ldflags="-s -w" -o /out/hoocloak ./cmd/hoocloak

FROM scratch
USER 65532:65532
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/hoocloak /hoocloak
ENTRYPOINT ["/hoocloak"]
CMD ["serve", "--config", "/etc/hoocloak/config.yaml"]
