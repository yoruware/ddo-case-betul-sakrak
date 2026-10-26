FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/verify .

FROM alpine:3.20
RUN adduser -D -u 10001 app
COPY --from=build /out/verify /usr/local/bin/verify
USER app
ENTRYPOINT ["verify"]