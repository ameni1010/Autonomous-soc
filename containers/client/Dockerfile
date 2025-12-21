FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    openssh-client \
    sshpass \
    curl \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY attack.sh /app/
RUN chmod +x /app/attack.sh

CMD ["tail", "-f", "/dev/null"]
