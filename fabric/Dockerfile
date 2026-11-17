# mrc-fabric: MRC ラボのデータプレーン (ネットワークネームスペース + SRv6 uSID + eBPF) と操作盤
# build context は fabric/: docker build -t localhost:5000/mrc-fabric:VER fabric
FROM debian:trixie-slim AS bpf
RUN apt-get update && apt-get install -y --no-install-recommends clang llvm libbpf-dev linux-libc-dev \
 && rm -rf /var/lib/apt/lists/*
COPY bpf/port.bpf.c /src/
RUN clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c /src/port.bpf.c -o /src/port.bpf.o

FROM python:3.14-slim-trixie
LABEL org.opencontainers.image.source=https://github.com/sasakipochi/k3s-mrc-lab \
      org.opencontainers.image.description="MRC lab fabric (network namespaces + SRv6 uSID + eBPF) and console" \
      org.opencontainers.image.licenses=MIT
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 bpftool tcpdump procps \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=bpf /src/port.bpf.o /app/bpf/port.bpf.o
COPY topo.py mrc.py controller.py /app/
COPY static/ /app/static/
ENV PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["python3", "/app/controller.py"]
