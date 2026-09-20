# Two-stage build: a static binary on a small alpine runtime.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/sixup .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=build /out/sixup /usr/local/bin/sixup
COPY LICENSE NOTICE /usr/share/doc/sixup/
# State directory: DUID, keys, leases, ULA. Mount it as a volume, or recreating the container changes the DUID and the ISP may hand out a different prefix.
VOLUME /var/lib/sixup
ENTRYPOINT ["/usr/local/bin/sixup"]
CMD ["-h"]
