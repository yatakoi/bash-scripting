#!/bin/sh

#********************************************************************
# Переменные
FTPCON="20:21" # Команды FTP
FTPDATA="49152:65535" # Данные FTP

# IP адреса
HOME="" # Admin's Home
ALIASWEB="193.106.174.7" # IP адрес интерфейса, на котором будут висеть сайты
ALIASDNS="" # 2-ой IP адрес, чтобы нормально работал DNS
ALIASLAN="" # IP в локалке (если есть)
ALIASLOOP="127.0.0.1" # IP LoopBack (замыкание на себя)

# Интерфейсы
INTWEB="ens192" # Название интерфейса, на котором будут висеть сайты
INTDNS="" # Интефейс для DNS2
INTLAN="" # Интерфейс локальной сети (если есть)
#********************************************************************

export IPT="iptables"

#Очистка всех фепочек iptables
$IPT -F
$IPT -F -t nat
$IPT -F -t mangle
$IPT -X
$IPT -t nat -X
$IPT -t mangle -X

#********************************************************************
# Защита от спуфинга (подмена адреса отправителя)
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 1 > /proc/sys/net/ipv4/conf/default/rp_filter

# Разрешаем исходящий трафик и запрещаем весь входящий и транзитный:
$IPT -P INPUT DROP
$IPT -P OUTPUT ACCEPT
$IPT -P FORWARD DROP

# Разрешаем уже инициированные соединения, а также дочерние от них:
$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

#Отбрасываем все пакеты, которые не могут быть идентивицированы
#и поэтому не могут иметь определенного статуса.
$IPT -A INPUT -m state --state INVALID -j DROP

# Запрет FIN-сканирования
$IPT -A INPUT –p tcp –m tcp --tcp-flags FIN,ACK FIN -j DROP

# Запрет X-сканирования
$IPT -A INPUT –p tcp –m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG –j DROP

# Запрет N-сканирования
$IPT -A INPUT –p tcp –m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE –j DROP

# Запрещаем сканирование NMAP-ом
$IPT -I INPUT -p tcp -m osf --genre NMAP -j DROP

#
$IPT -A INPUT -p ALL -m state --state ESTABLISHED,RELATED -j ACCEPT # Дропаем битые пакеты, которые идут на вшнешний мир, если когда-нибуть будет NAT
$IPT -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j REJECT

# Защита ssh от перебора паролей
$IPT -N FAILLOG
$IPT -A FAILLOG -j LOG --log-prefix "iptables blocked: " --log-level 7
$IPT -A FAILLOG -j DROP
$IPT -A INPUT -p tcp -m tcp --dport 1911 -m state --state NEW -m recent --update --seconds 60 --hitcount 3 --name DEFAULT --rsource -j FAILLOG
#********************************************************************

#********************************************************************
# Разрешаем все для себя
$IPT -A INPUT -s $ALIASLOOP -d $ALIASLOOP -j ACCEPT
$IPT -A INPUT -s $ALIASWEB -d $ALIASWEB -j ACCEPT
$IPT -A INPUT -s $ALIASLAN -d $ALIASLAN -j ACCEPT
$IPT -A INPUT -s $ALIASDNS -d $ALIASDNS -j ACCEPT
#
$IPT -A INPUT -p icmp --icmp-type 8 -m limit --limit 10/s --limit-burst 20 -j ACCEPT	# ICMP
$IPT -A INPUT -p icmp --icmp-type 11 -m limit --limit 10/s --limit-burst 20 -j ACCEPT	# ICMP
#********************************************************************

#********************************************************************
# Разрешаем разные протоколы:
$IPT -A INPUT -i $INTWEB -p tcp --dport 1911 -j ACCEPT			# Разрешаем SSH
$IPT -A INPUT -i $INTWEB -p tcp --dport 80 -j ACCEPT			# Разрешаем HTTP
$IPT -A INPUT -i $INTWEB -p tcp --dport 443 -j ACCEPT			# Разрешаем HTTPS
$IPT -A INPUT -i $INTWEB -p udp --dport 53 -j ACCEPT			# Разрешаем DNS
$IPT -A INPUT -i $INTDNS -p udp --dport 53 -j ACCEPT 			# Разрешаем DNS
$IPT -A INPUT -i $INTWEB -p tcp --dport 1500 -j ACCEPT  		# Разрешаем ISPmanager
$IPT -A INPUT -i $INTWEB -p tcp --dport 110 -j ACCEPT			# Разрешаем POP3
$IPT -A INPUT -i $INTWEB -p tcp --dport 993 -j ACCEPT			# Разрешаем POP3s/IMAPs
$IPT -A INPUT -i $INTWEB -p tcp --dport 25 -j ACCEPT			# Разрешаем SMTP
$IPT -A INPUT -i $INTWEB -p tcp --dport 465 -j ACCEPT			# Разрешаем SMTPs
$IPT -A INPUT -i $INTWEB -p tcp --dport 143 -j ACCEPT			# Разрешаем IMAP
$IPT -A INPUT -i $INTWEB -p tcp --dport $FTPDATA -j ACCEPT		# Разрешаем FTP Data
$IPT -A INPUT -i $INTWEB -p tcp --dport $FTPCON -j ACCEPT		# Разрешаем FTP


# local loopback:
$IPT -A INPUT -i lo -j ACCEPT

# Разрешаем ping:
$IPT -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
$IPT -A INPUT -p icmp --icmp-type source-quench -j ACCEPT
$IPT -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT

# Блокируем все остальное
$IPT -A INPUT -j DROP

#Вывод информации о состоянии таблиц
route -n
$IPT -L
$IPT -L -v -n
$IPT -L -v -n -t nat
