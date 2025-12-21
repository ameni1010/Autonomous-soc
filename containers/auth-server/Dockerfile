FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openssh-server \
    sudo \
    python3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create users
RUN useradd -m -s /bin/bash user1 && echo "user1:password123" | chpasswd
RUN useradd -m -s /bin/bash admin && echo "admin:admin123" | chpasswd
RUN usermod -aG sudo admin

# Configure passwordless sudo for admin (for demo purposes)
RUN echo "admin ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Configure SSH
RUN mkdir /var/run/sshd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Create log directory
RUN mkdir -p /logs

# Copy logging script
COPY log_auth.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/log_auth.sh

# Start script
COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 22

CMD ["/start.sh"]
