FROM --platform=$BUILDPLATFORM node:24-alpine@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85 AS login
WORKDIR /src/ui/login
COPY ui/login/package.json ui/login/package-lock.json ./
RUN --mount=type=cache,id=hoocloak-npm,target=/root/.npm,sharing=locked npm ci --no-audit --no-fund
COPY ui/login/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.26.9-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS build
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
