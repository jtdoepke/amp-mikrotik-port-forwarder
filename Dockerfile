FROM gcr.io/distroless/static-debian12

ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/amp-port-sync /amp-port-sync

USER nonroot:nonroot

ENTRYPOINT ["/amp-port-sync"]
