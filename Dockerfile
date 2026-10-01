FROM gcr.io/distroless/static-debian12:nonroot

ARG TARGETOS
ARG TARGETARCH

USER 20000:20000
COPY --chmod=0555 ${TARGETOS}/${TARGETARCH}/external-dns-vultr-webhook /opt/external-dns-vultr-webhook/app

ENTRYPOINT ["/opt/external-dns-vultr-webhook/app"]
