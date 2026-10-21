# syntax=docker/dockerfile:1
# Production image: serk-api, serk-migrate and serk-relay only. The
# development token tool (cmd/serk-devtoken) is deliberately not built here.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/serk-api ./cmd/serk-api \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/serk-migrate ./cmd/serk-migrate \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/serk-relay ./cmd/serk-relay

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/serk-api /out/serk-migrate /out/serk-relay /
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/serk-api"]
