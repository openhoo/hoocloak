FROM --platform=$BUILDPLATFORM node:24-alpine@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd AS login
WORKDIR /src/ui/login
COPY ui/login/package.json ui/login/package-lock.json ./
RUN npm ci
COPY ui/login/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY --from=login /src/internal/idp/ui/dist ./internal/idp/ui/dist
ARG VERSION
ARG TARGETOS
ARG TARGETARCH
RUN VERSION="${VERSION:-$(cat internal/version/version)}" && \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -tags no_otel -trimpath \
      -ldflags="-s -w -X github.com/openhoo/hoocloak/internal/version.Value=${VERSION}" \
      -o /out/hoocloak ./cmd/hoocloak

FROM scratch
USER 65532:65532
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/hoocloak /hoocloak
EXPOSE 8080
ENTRYPOINT ["/hoocloak"]
CMD ["serve", "--config", "/etc/hoocloak/config.yaml"]
