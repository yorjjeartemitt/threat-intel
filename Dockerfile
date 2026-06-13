FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    gcc \
    libgtk-3-dev \
    libcurl4-openssl-dev \
    libcjson-dev \
    libsqlite3-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN gcc main.c api.c db.c -o threat-intel \
    $(pkg-config --cflags --libs gtk+-3.0) \
    -lcurl -lcjson -lsqlite3

CMD ["./threat-intel"]
