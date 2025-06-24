#!/bin/bash

cp -r /ossec-etc/* /var/ossec/etc
cp /ossec-data/ossec.conf /var/ossec/etc/ossec.conf

exec /var/ossec/bin/wazuh-agentd -f