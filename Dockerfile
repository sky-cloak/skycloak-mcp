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
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/skycloak-mcp"]
CMD ["--transport", "stdio"]
