
FROM golang:1.10

WORKDIR /go/src/gitlab.morningconsult.com/mci/docker-credential-vault-login

COPY . .

RUN make

ENTRYPOINT "/bin/bash"