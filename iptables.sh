#!/bin/sh

#********************************************************************
# Переменные
FTPCON="20:21"			  # Команды FTP
FTPDATA="49152:65535"	# Данные FTP

# IP адреса
ALIASWEB="ip_address"	#       IP адрес интерфейса, на котором будут сайты
#ALIASDNS="ip_address"				# 2-ой IP адрес для второго DNS
#ALIASLAN="ip_address"				# IP в локалке (если есть)
ALIASLOOP="127.0.0.1"		      # IP loopback (замыкание на себя)

# Интерфейсы
INTWEB="eth0"	    # Название интерфейса с "белым" IP
#INTDNS="ethX"		# Интефейс для DNS2
#INTLAN="ethY"		# Интерфейс локальной сети (если есть)
#********************************************************************

#Очистка всех фепочек iptables
iptables -F
iptables -F -t nat
iptables -F -t mangle
iptables -X
iptables -t nat -X
iptables -t mangle -X

#********************************************************************
# Защита от спуфинга (подмена адреса отправителя)
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 1 > /proc/sys/net/ipv4/conf/default/rp_filter

# Разрешаем исходящий трафик и запрещаем весь входящий и транзитный
iptables -P INPUT DROP
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP

###################################################НАЧАЛО ПРАВИЛА ДЛЯ ВХОДЯЩИХ##################################

# Разрешаем уже инициированные соединения, а также дочерние от них
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

#Отбрасываем все пакеты, которые не могут быть идентифицированы
#и поэтому не могут иметь определенного статуса.
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP


### DROP спуфинг пакетов
iptables -A INPUT -s 10.0.0.0/8 -j DROP
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -j DROP
iptables -A INPUT -s 127.0.0.0/8 -j DROP
iptables -A INPUT -s 192.168.0.0/24 -j DROP
iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -d 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP
iptables -A INPUT -d 240.0.0.0/5 -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -d 0.0.0.0/8 -j DROP
iptables -A INPUT -d 239.255.255.0/24 -j DROP
iptables -A INPUT -d 255.255.255.255 -j DROP

# flooding of RST packets, smurf attack Rejection
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

# flooding of RST packets, smurf attack Rejection
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

#********************************************************************
# Защита от сканирования
# IP атакующего будет залочен на 24 часа (3600 x 24 = 86400 сек.)
iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP

# Удалить IP атакующего через 24 часа
iptables -A INPUT -m recent --name portscan --remove
iptables -A FORWARD -m recent --name portscan --remove

# Добавление сканирующего в список portscan, уведомление об этом в консоли(не SSH) и запись в лог
iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:"
iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:"
iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP
#********************************************************************

#********************************************************************
# Разрешаем все для себя
iptables -A INPUT -s $ALIASLOOP -d $ALIASLOOP -j ACCEPT
iptables -A INPUT -s $ALIASWEB -d $ALIASWEB -j ACCEPT
#iptables -A INPUT -s $ALIASLAN -d $ALIASLAN -j ACCEPT
#iptables -A INPUT -s $ALIASDNS -d $ALIASDNS -j ACCEPT
#********************************************************************

#********************************************************************
# Разрешаем разные протоколы:
iptables -A INPUT -i $INTWEB -p tcp --dport 22 -j ACCEPT			# Разрешаем SSH (настоятельно рекомендую сменить порт, например, на 7777)
iptables -A INPUT -i $INTWEB -p tcp --dport 80 -j ACCEPT			# Разрешаем HTTP
iptables -A INPUT -i $INTWEB -p tcp --dport 443 -j ACCEPT			# Разрешаем HTTPS
iptables -A INPUT -i $INTWEB -p udp --dport 53 -j ACCEPT		    	# Разрешаем DNS
iptables -A INPUT -i $INTWEB -p tcp --dport 53 -j ACCEPT		    	# Разрешаем DNS
#iptables -A INPUT -i $INTDNS -p udp --dport 53 -j ACCEPT 	    	# Разрешаем DNS
iptables -A INPUT -i $INTWEB -p tcp --dport 1500 -j ACCEPT      	# Разрешаем ISPmanager
iptables -A INPUT -i $INTWEB -p tcp --dport 110 -j ACCEPT		    	# Разрешаем POP3
iptables -A INPUT -i $INTWEB -p tcp --dport 993 -j ACCEPT		    	# Разрешаем POP3s/IMAPs
iptables -A INPUT -i $INTWEB -p tcp --dport 25 -j ACCEPT		    	# Разрешаем SMTP
iptables -A INPUT -i $INTWEB -p tcp --dport 465 -j ACCEPT			    # Разрешаем SMTPs
iptables -A INPUT -i $INTWEB -p tcp --dport 587 -j ACCEPT			    # Разрешаем SMTP MSA
iptables -A INPUT -i $INTWEB -p tcp --dport 143 -j ACCEPT			    # Разрешаем IMAP
iptables -A INPUT -i $INTWEB -p tcp --dport $FTPDATA -j ACCEPT		# Разрешаем FTP Data
iptables -A INPUT -i $INTWEB -p tcp --dport $FTPCON -j ACCEPT		  # Разрешаем FTP
iptables -A INPUT -i $INTWEB -p tcp --dport 3306 -j ACCEPT			  # Разрешаем MariaDB
iptables -A INPUT -i $INTWEB -p tcp --dport 5432 -j ACCEPT			  # Разрешаем PostgreSQL
#********************************************************************

# Разрешаем входящие для loopback
iptables -A INPUT -i lo -j ACCEPT

# Блокируем все остальное
iptables -A INPUT -j REJECT

################################################### КОНЕЦ ПРАВИЛА ДЛЯ ВХОДЯЩИХ ##################################


################################################### ПРАВИЛА ДЛЯ ИСХОДЯЩИХ ###################################################

# Разрешаем исходящие для loopback
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Разрешаем наружу разные протоколы:
# Разрешаем наружу разные протоколы:
iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT		  	# Разрешаем SSH
iptables -A OUTPUT -p tcp --dport 7777 -j ACCEPT	  	# Разрешаем SSH для служебного использования
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT		  	# Разрешаем HTTP
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT		  	# Разрешаем HTTPS
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT		  	# Разрешаем DNS
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT		  	# Разрешаем DNS
#iptables -A OUTPUT -p udp --dport 53 -j ACCEPT 	  	# Разрешаем DNS
iptables -A OUTPUT -p tcp --dport 1500 -j ACCEPT  		# Разрешаем ISPmanager
iptables -A OUTPUT -p tcp --dport 110 -j ACCEPT		  	# Разрешаем POP3
iptables -A OUTPUT -p tcp --dport 993 -j ACCEPT		  	# Разрешаем POP3s/IMAPs
iptables -A OUTPUT -p tcp --dport 25 -j ACCEPT	  		# Разрешаем SMTP
iptables -A OUTPUT -p tcp --dport 465 -j ACCEPT	  		# Разрешаем SMTPs
iptables -A OUTPUT -p tcp --dport 587 -j ACCEPT	  		# Разрешаем SMTP MSA
iptables -A OUTPUT -p tcp --dport 143 -j ACCEPT		  	# Разрешаем IMAP
iptables -A OUTPUT -p tcp --dport $FTPDATA -j ACCEPT	# Разрешаем FTP Data
iptables -A OUTPUT -p tcp --dport $FTPCON -j ACCEPT		# Разрешаем FTP
iptables -A OUTPUT -p tcp --dport 3306 -j ACCEPT	  	# Разрешаем MariaDB
iptables -A OUTPUT -p tcp --dport 5432 -j ACCEPT	  	# Разрешаем PostgreSQL

# Разрешаем пинг
iptables -A OUTPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

# Блокируем все остальное
iptables -A OUTPUT -j REJECT

################################################### КОНЕЦ ПРАВИЛА ДЛЯ ИСХОДЯЩИХ ###################################################

# REJECT forward-трафика
iptables -A FORWARD -j REJECT

# Вывод информации о состоянии таблиц
#route -n
#iptables -L -v -n
