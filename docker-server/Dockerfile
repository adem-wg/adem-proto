# syntax=docker/dockerfile:1

FROM golang:1.19
ENV GO111MODULE=on
ENV EMBLEM_TIMEOUT=0

# Set destination for COPY
WORKDIR /app

RUN apt update && apt install openssl -y

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd
COPY pkg/ ./pkg

# Build
RUN CGO_ENABLED=0 GOOS=linux go build github.com/adem-wg/adem-proto/cmd/emblemserver

EXPOSE 6060/udp

# Run
RUN mkdir /var/emblemserver
RUN mkdir /var/emblemlog
RUN touch /var/emblemlog/system.log
RUN openssl ecparam -genkey -name secp521r1 -noout -out private_emb.pem
RUN openssl ec -in private_emb.pem -pubout -out /var/emblemserver/public_emb.pem

CMD tail -f /var/emblemlog/system.log | ./emblemserver -skey private_emb.pem -alg ES512 -port 6060 -end /var/emblemserver/end_*.jws -proto /var/emblemserver/emblem.json -timeout ${EMBLEM_TIMEOUT}
