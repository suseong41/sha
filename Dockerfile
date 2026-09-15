FROM golang:1.27-alpine AS build
WORKDIR /src
COPY . .

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /webscan ./cmd/webscan

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /webscan /webscan

USER 65532:65532
EXPOSE 8080

ENTRYPOINT ["/webscan", "-addr", "0.0.0.0:8080"]