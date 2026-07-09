FROM golang:1.25.12-alpine AS build
WORKDIR /app
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /kde-auth ./cmd/server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /kde-auth /usr/local/bin/kde-auth
COPY migrations ./migrations
EXPOSE 3001
CMD ["kde-auth"]
