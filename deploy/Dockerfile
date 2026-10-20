# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/serk-api ./cmd/serk-api \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/serk-migrate ./cmd/serk-migrate

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/serk-api /out/serk-migrate /
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/serk-api"]
