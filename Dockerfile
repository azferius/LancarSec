# LancarSec container image.
#
# ---------------------------------------------------------------------------
# Why alpine and not distroless/static
# ---------------------------------------------------------------------------
# Decided against the code that is actually in this tree, not against a
# generic "Go binary" template.
#
#  1. Ports 80 and 443 are HARD-CODED. core/server/serve.go pins Addr: ":80"
#     (lines 42 and 61) and Addr: ":443" (line 70). There is no config knob to
#     move them, so the usual non-root escape hatch -- listen high, publish
#     with `-p 80:8080` -- is not available. A non-root container user must
#     therefore hold CAP_NET_BIND_SERVICE. Attaching that as a *file*
#     capability means running `setcap` inside the stage that ships the
#     binary. distroless/static has no package manager and no libcap, so the
#     only distroless route is to setcap in a builder stage and rely on
#     `COPY --from` preserving the security.capability xattr. BuildKit does;
#     the classic builder and some registry/runtime combinations silently
#     drop it, and the failure mode is a container that boots and then cannot
#     bind. Alpine sets the capability deterministically in the final layer.
#
#  2. The admin interface IS a stdin TUI. core/server/monitor.go:290 reads
#     operator commands with bufio.NewScanner(os.Stdin) and repaints the
#     screen through core/screen. config.json is edited in
#     place and re-read by monitor.go:405. Day-to-day operation means
#     `docker exec -it <ctr> sh` to edit that file, read crash.log, and drop
#     TLS material in. distroless ships no shell, so that entire workflow
#     disappears -- and it does not buy much here, because the process is
#     designed to take commands from an interactive console anyway.
#
#  3. Size is not the tiebreaker. The stripped linux/amd64 binary measures
#     8,097,976 bytes (CGO_ENABLED=0, -trimpath, -ldflags="-s -w"). alpine
#     3.24 adds roughly 8 MB where distroless/static adds roughly 2 MB: about
#     6 MB on a ~16 MB image.
#
# To switch to distroless anyway (headless deployments with a pre-baked
# config, orchestrated by something that can grant NET_BIND_SERVICE through
# securityContext rather than file caps), replace the runtime stage with:
#
#     FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
#     WORKDIR /app
#     COPY --from=builder --chown=65532:65532 /out/lancarsec /usr/local/bin/lancarsec
#     COPY --from=builder --chown=65532:65532 /src/global/ /app/global/
#     USER 65532:65532
#     ENTRYPOINT ["/usr/local/bin/lancarsec"]
#
# ...and accept that (a) you get no shell, (b) you must grant
# NET_BIND_SERVICE at run time because there is no setcap, and (c) /app must
# be a writable mount because the image cannot chown it for you.
#
# ---------------------------------------------------------------------------
# Hard runtime requirements this image satisfies
# ---------------------------------------------------------------------------
#  * CA CERTIFICATES ARE MANDATORY, not optional. core/config/init.go:238
#    (VersionCheck) calls http.Get("https://raw.githubusercontent.com/...")
#    and core/config/init.go:225-227 PANICS when it returns an error. The
#    three fingerprint tables are fetched over HTTPS too (init.go:104-106),
#    though those errors are discarded. A bare `FROM scratch` image panics
#    on boot. ca-certificates is installed below.
#
#  * THE WORKING DIRECTORY MUST BE WRITABLE. main.go:21 opens crash.log with
#    O_CREATE and log.Fatal()s if that fails; core/pnc/panicHandler.go:16
#    does the same. A read-only /app kills the process before it serves a
#    single request. /app is chowned to the runtime uid here; do not run this
#    image with --read-only unless you also mount a writable /app.
#
#  * config.json MUST BE BIND-MOUNTED. It is the only file this tree reads
#    from the working directory (core/config/init.go:27, and again on reload
#    at core/server/monitor.go:405). Nothing reads global/ or assets/ today:
#    the fingerprint JSON is fetched over HTTPS and the challenge markup is
#    inlined as Go string literals in core/server/middleware.go. They are
#    still copied in, because .dockerignore deliberately keeps them in the
#    build context for the wave that bundles them locally.
#
#    If config.json is absent the proxy does NOT fall back to a default. It
#    enters the interactive generator (core/config/generate.go). With no TTY
#    every utils.Ask* helper takes its default, because a failed Scan returns
#    "" (core/utils/text.go:99-103) -- including Cloudflare=false and empty
#    certificate/key paths. Startup then panics in
#    tls.LoadX509KeyPair("", "") at core/config/init.go:135. Mount a real
#    config.json.
#
# ---------------------------------------------------------------------------
# Build and run
# ---------------------------------------------------------------------------
#   docker build -t lancarsec:dev --build-arg VERSION="$(git describe --tags --always)" .
#
#   docker run -d --name lancarsec \
#     -p 80:80 -p 443:443 \
#     -v "$PWD/config.json:/app/config.json" \
#     -v "$PWD/tls:/etc/lancarsec/tls:ro" \
#     lancarsec:dev
#
# Ports: the binary runs as uid 65532 and carries
# cap_net_bind_service=+ep, which is inside Docker's default bounding set, so
# plain `docker run` binds :80 and :443 with no extra flags. If you harden
# with --cap-drop=ALL you MUST add back --cap-add=NET_BIND_SERVICE. Under
# Kubernetes use securityContext.capabilities.add: ["NET_BIND_SERVICE"], and
# under rootless Podman either that or
# --sysctl net.ipv4.ip_unprivileged_port_start=0.
#
# Console: the operator TUI needs a TTY on stdin. Either run the container
# with `-it`, or run it detached and use `docker exec -it lancarsec sh`.


# ===========================================================================
# Stage 1 -- builder
# ===========================================================================
# golang:1.25-alpine, digest-pinned. At the time of writing this digest is
# also what golang:1.25.14-alpine3.24 resolves to, which keeps the builder
# and the runtime stage on the same Alpine 3.24 base.
FROM golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS builder

ENV CGO_ENABLED=0 \
    GOFLAGS=-mod=readonly

WORKDIR /src

# Dependency layer first, on its own, so that editing a .go file does not
# invalidate the module download. go.mod and go.sum are the only inputs here.
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Source layer. .dockerignore already keeps .git, key material, config.json,
# databases, logs and host binaries out of the context.
COPY . .

# Populated by BuildKit for the target platform; the defaults keep the
# classic builder working too.
ARG TARGETOS=linux
ARG TARGETARCH=amd64

# Stamped into main.Fingerprint (declared in main.go:15, surfaced on the
# admin stats endpoint at core/server/middleware.go:327). Build metadata
# only -- it feeds no proxy decision.
ARG VERSION=docker

RUN GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build \
      -trimpath \
      -buildvcs=false \
      -ldflags="-s -w -X main.Fingerprint=${VERSION}" \
      -o /out/lancarsec \
      .


# ===========================================================================
# Stage 2 -- runtime
# ===========================================================================
# alpine:3.24, digest-pinned. Same base as the builder image above.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS runtime

LABEL org.opencontainers.image.title="LancarSec" \
      org.opencontainers.image.description="HTTP reverse proxy with DDoS mitigation and TLS fingerprinting" \
      org.opencontainers.image.licenses="GPL-2.0-only" \
      org.opencontainers.image.source="https://github.com/azferius/lancarsec"

# ca-certificates: mandatory, see the VersionCheck note at the top.
# The unprivileged account owns /app because the process writes crash.log and
# rewrites config.json there.
RUN apk add --no-cache ca-certificates \
 && addgroup -S -g 65532 lancarsec \
 && adduser  -S -u 65532 -G lancarsec -h /app -s /sbin/nologin lancarsec

WORKDIR /app

COPY --from=builder /out/lancarsec /usr/local/bin/lancarsec

# Not read by any code path in this tree yet; carried so the wave that reads
# fingerprints from disk instead of over HTTPS does not need a Dockerfile
# change. LICENSE ships because this is GPL v2 and the image is a binary
# distribution.
COPY --chown=65532:65532 global/ /app/global/
COPY --chown=65532:65532 assets/html/ /app/assets/html/
COPY LICENSE /app/LICENSE

# libcap is added and removed inside a single RUN so it leaves no bytes in
# the layer. setcap must happen in this stage: a capability applied in the
# builder would have to survive COPY --from, which is not portable.
RUN apk add --no-cache --virtual .setcap libcap \
 && setcap 'cap_net_bind_service=+ep' /usr/local/bin/lancarsec \
 && apk del .setcap \
 && chown 65532:65532 /app

USER 65532:65532

EXPOSE 80 443

# No HEALTHCHECK: every endpoint this proxy answers on either requires a
# Host header matching a configured domain or the admin secret, so any probe
# baked into the image would be wrong for most deployments. Add one in the
# compose/k8s layer where the domain is known.

ENTRYPOINT ["/usr/local/bin/lancarsec"]
