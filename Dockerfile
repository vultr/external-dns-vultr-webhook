FROM gcr.io/distroless/static-debian12:nonroot

USER 20000:20000
COPY --chmod=0555 external-dns-vultr-webhook /opt/external-dns-vultr-webhook/app

ENTRYPOINT ["/opt/external-dns-vultr-webhook/app"]
