FROM golang:alpine as builder

COPY src /go/src/github.com/egeland/sslcertcheck
WORKDIR /go/src/github.com/egeland/sslcertcheck
RUN go build

FROM alpine
LABEL maintainer="egeland@gmail.com"
LABEL repo="https://github.com/egeland/sslcertcheck"
RUN apk --no-cache add ca-certificates
# FROM gcr.io/distroless/base
COPY --from=builder /go/src/github.com/egeland/sslcertcheck/sslcertcheck app
CMD ["./app"]
