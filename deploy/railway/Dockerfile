# syntax=docker/dockerfile:1
# STAGING / TEST image for Railway. NOT the production image (deploy/Dockerfile).
# It adds the synthetic-data seed, the development token tool, psql and a
# small supervisor so the isolated signer and the API share one container
# (Railway services cannot share a unix socket). The API is started with
# SERK_ENV=staging and refuses production settings it is not given.
FROM golang:1.26.10-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN for c in serk-api serk-migrate serk-signer serk-seed serk-devtoken; do \
      CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/$c ./cmd/$c || exit 1; done

FROM alpine:3.22
RUN apk add --no-cache bash postgresql16-client ca-certificates tzdata \
 && adduser -D -H -u 10001 serk
COPY --from=build /out/ /usr/local/bin/
COPY deploy/00-roles.sql deploy/01-schema-owner.sql deploy/02-restrict-advisory-locks.sql /opt/serk/sql/
COPY deploy/railway/entrypoint.sh /opt/serk/entrypoint.sh
RUN chmod 0555 /opt/serk/entrypoint.sh
USER serk
ENV SERK_ENV=staging
EXPOSE 8080
ENTRYPOINT ["/opt/serk/entrypoint.sh"]
