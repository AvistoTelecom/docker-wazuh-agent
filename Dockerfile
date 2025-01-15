FROM  bitnami/minideb@sha256:bce8004f7da6547bc568e92895e1b3a3835e6dba48283fbbf9b3f66c1d166c6d as builder
COPY requirements.txt /tmp
RUN install_packages python3-pip python3-setuptools python3-dev gcc && \
     python3 -m pip wheel -w /tmp/wheel -r /tmp/requirements.txt

FROM bitnami/minideb@sha256:bce8004f7da6547bc568e92895e1b3a3835e6dba48283fbbf9b3f66c1d166c6d
LABEL maintainer="support@opennix.ru"
LABEL description="Wazuh Docker Agent"
ARG AGENT_VERSION="4.9.2-1"
ENV JOIN_MANAGER_MASTER_HOST=""
ENV JOIN_MANAGER_WORKER_HOST=""
ENV VIRUS_TOTAL_KEY=""
ENV JOIN_MANAGER_PROTOCOL="https"
ENV JOIN_MANAGER_USER=""
ENV JOIN_MANAGER_PASSWORD=""
ENV JOIN_MANAGER_API_PORT="55000"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV YARA_VERSION=4.5.2
RUN install_packages \
  procps curl apt-transport-https gnupg2 inotify-tools python3-docker python3-setuptools python3-pip auditd audispd-plugins make automake gcc autoconf libtool libssl-dev pkg-config jq && \
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && \
  echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list && \
  install_packages wazuh-agent=${AGENT_VERSION}  && \
  echo "deb https://deb.debian.org/debian-security/ bullseye-security main contrib non-free" >> /etc/apt/sources.list && \
  mkdir -p /usr/share/man/man1 && \
  install_packages openjdk-11-jdk
RUN curl -LO https://github.com/VirusTotal/yara/archive/v${YARA_VERSION}.tar.gz && \
  tar -xvzf v${YARA_VERSION}.tar.gz -C /usr/local/bin/ && rm -f v${YARA_VERSION}.tar.gz && \
  cd /usr/local/bin/yara-${YARA_VERSION} && \
  ./bootstrap.sh && sync && ./configure && make && make install && make check && \
  echo "/usr/local/lib" >> /etc/ld.so.conf && ldconfig

COPY *.py *.jinja2  /var/ossec/
COPY yara.sh /var/ossec/active-response/bin/
WORKDIR /var/ossec/
COPY --from=builder /tmp/wheel /tmp/wheel
RUN pip3 install --break-system-packages --no-index /tmp/wheel/*.whl && \
  chmod +x /var/ossec/deregister_agent.py && \
  chmod +x /var/ossec/register_agent.py && \
  apt-get clean autoclean && \
  apt-get autoremove -y && \
  rm -rf /var/lib/{apt,dpkg,cache,log}/ && \
  rm -rf  /tmp/* /var/tmp/* /var/log/* && \
  chown -R wazuh:wazuh /var/ossec/ && \
  chmod 750 /var/ossec/active-response/bin/yara.sh && \
  chown root:wazuh /var/ossec/active-response/bin/yara.sh
RUN mkdir -p /var/ossec/yara/rules && \
  curl 'https://valhalla.nextron-systems.com/api/v1/get' \
  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
  -H 'Accept-Language: en-US,en;q=0.5' \
  --compressed \
  -H 'Referer: https://valhalla.nextron-systems.com/' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'DNT: 1' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' \
  --data 'demo=demo&apikey=1111111111111111111111111111111111111111111111111111111111111111&format=text' \
  -o /var/ossec/yara/rules/yara_rules.yar && \
  chown -R wazuh:wazuh /var/ossec/yara
RUN ls -la /var/ossec
EXPOSE 5000
ENTRYPOINT ["./register_agent.py"]
