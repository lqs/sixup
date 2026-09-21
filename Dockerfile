# Two-stage build: a static binary on a small alpine runtime.
# The compiler always runs on the build platform and cross-compiles, so building for
# another architecture needs no emulation; the runtime stage only copies files.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETARCH TARGETVARIANT VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go LICENSE NOTICE ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH="$TARGETARCH" GOARM="${TARGETVARIANT#v}" \
	go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/sixup .

FROM alpine:3.24
COPY --from=build /out/sixup /usr/local/bin/sixup
# State directory: DUID, keys, leases, ULA. Mount it as a volume, or recreating the container changes the DUID and the ISP may hand out a different prefix.
VOLUME /var/lib/sixup
ENTRYPOINT ["/usr/local/bin/sixup"]
CMD ["-h"]
