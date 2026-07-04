# SPDX-License-Identifier: AGPL-3.0-or-later
# goreleaser copies the prebuilt static binary in; there are no RUN steps,
# so multi-arch images build without emulation.
FROM gcr.io/distroless/static:nonroot
COPY portolan /portolan
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/portolan"]
CMD ["serve"]
