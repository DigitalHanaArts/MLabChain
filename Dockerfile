FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake libssl-dev libsqlite3-dev libboost-all-dev python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/mera
COPY . .
RUN ./build.sh && python3 -m pip install --no-cache-dir -r requirements.txt
ENTRYPOINT ["./build/mera_core"]
