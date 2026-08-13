# syntax=docker/dockerfile:1
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/skycloak-mcp ./cmd/skycloak-mcp

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/skycloak-mcp /usr/local/bin/skycloak-mcp
# Numeric, not the name `nonroot`: with runAsNonRoot set, the kubelet has to
# verify the user is not root and cannot do that from a name, so it refuses to
# start the container. This is the uid the base image already uses.
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/skycloak-mcp"]
CMD ["--transport", "stdio"]
