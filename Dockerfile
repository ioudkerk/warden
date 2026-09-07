# Warden, as a container.
#
# Built against the Go floor from ADR-0001 rather than the newest toolchain. The floor
# is a promise to self-hosters building from source, and a promise nothing exercises is
# one that breaks quietly: building here at 1.23 is what keeps cmd/warden/gomod_test.go
# honest about more than the go.mod text.

FROM golang:1.23-alpine AS build

WORKDIR /src

# Dependencies first, so editing source does not re-download the module cache.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# VERSION is passed in because .git is not in the build context — a build should not
# need the repository's history, and shipping it would put every branch name and commit
# message inside the image.
ARG VERSION=devel
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/warden ./cmd/warden

# distroless/static: no shell, no package manager, no libc. There is nothing in here to
# exec if someone finds a way to ask, and the CA bundle it does carry is what the OIDC
# and SAML federation of M4 will need.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/warden /usr/local/bin/warden

# The migrations travel with the binary so that `warden` in a container and `warden` on
# a laptop are looking at the same SQL. The seed fixture and its manifest do not: they
# are development data, mounted by the compose file that wants them, so the published
# image carries no demo tenant waiting to be created.
COPY internal/store/migrations /usr/share/warden/migrations

USER nonroot:nonroot
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/warden"]
