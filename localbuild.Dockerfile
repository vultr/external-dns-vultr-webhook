FROM gcr.io/distroless/static-debian11:nonroot
USER 20000:20000
ADD --chmod=555 build/bin/external-dns-vultr-webhook /opt/external-dns-vultr-webhook/app

ENTRYPOINT ["/opt/external-dns-vultr-webhook/app"]