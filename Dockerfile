FROM golang:1.14 AS builder

WORKDIR /go/src/app
COPY . .

RUN sh build.sh

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /go/src/app/rancher_gitlab_proxy_linux rancher_gitlab_proxy_linux

CMD ["./rancher_gitlab_proxy_linux"]

EXPOSE 8888
