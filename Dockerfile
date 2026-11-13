FROM --platform=$BUILDPLATFORM node:24-alpine@sha256:a34ab6d7f6f4813f4d0c5469d74685604b962fbdbf5793a7bc7b4998ecb867c8 AS login
WORKDIR /src/ui/login
COPY ui/login/package.json ui/login/package-lock.json ./
RUN --mount=type=cache,id=hoocloak-npm,target=/root/.npm,sharing=locked npm ci --no-audit --no-fund
COPY ui/login/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,id=hoocloak-go-mod,target=/go/pkg/mod,sharing=shared go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY --from=login /src/internal/idp/ui/dist ./internal/idp/ui/dist
ARG VERSION
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,id=hoocloak-go-mod,target=/go/pkg/mod,sharing=shared \
    --mount=type=cache,id=hoocloak-go-build,target=/root/.cache/go-build,sharing=shared \
    VERSION="${VERSION:-$(cat internal/version/version)}" && \
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
