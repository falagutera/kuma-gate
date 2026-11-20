# --- build -------------------------------------------------------------------
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.* VERSION ./
RUN go mod download
COPY *.go CHANGELOG.md ./
COPY internal ./internal
COPY templates ./templates
COPY assets ./assets
ARG BUILD=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.build=${BUILD}" -o /kuma-gate .

# --- runtime -----------------------------------------------------------------
# distroless static: no shell, ca-certs and a nonroot user.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /kuma-gate /kuma-gate
USER 65532:65532
# Inside a container 127.0.0.1 would be unreachable: listen on every address.
ENV KUMAGATE_LISTEN=:3003
EXPOSE 3003
# -healthcheck follows KUMAGATE_LISTEN, so changing the port keeps the check right.
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD ["/kuma-gate", "-healthcheck"]
ENTRYPOINT ["/kuma-gate"]
