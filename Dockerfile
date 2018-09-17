
FROM golang:1.11

WORKDIR /go/src/github.com/morningconsult/docker-credential-vault-login

ARG TARGET_GOOS
ARG TARGET_GOARCH

COPY . .

ENV GOOS $TARGET_GOOS
ENV GOARCH $TARGET_GOARCH

RUN make

ENTRYPOINT "/bin/bash"