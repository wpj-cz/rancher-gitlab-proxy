#!/bin/bash

set -ex

go build -o rancher_gitlab_proxy main.go
CGO_ENABLED=0 GOOS=linux go build -o rancher_gitlab_proxy_linux main.go
