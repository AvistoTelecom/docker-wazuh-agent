FROM debian:bullseye-slim

LABEL maintainer=""
LABEL description="Minimal Wazuh Agent Docker image"

ARG AGENT_VERSION="4.12.0-1"

# Install required packages and Wazuh agent
RUN apt-get update && \
    apt-get install -y curl apt-transport-https gnupg2 procps inotify-tools && \
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && \
    echo "deb https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    apt-get install -y wazuh-agent=${AGENT_VERSION} && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Expose agent directory for configuration
VOLUME ["/var/ossec/etc"]

# Set working directory
WORKDIR /var/ossec

# Start the Wazuh agent
CMD ["/var/ossec/bin/wazuh-agentd", "-f"]