#!/bin/bash
#
# Этот цикл добавляет множество KVM-доменов в автозапуск

for i in lb-1 lb-2 pgsql-2 webserver-1 webserver-2 zabbix-1 zabbix-2; do virsh autostart --domain $i; done
