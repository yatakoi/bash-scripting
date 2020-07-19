#!/bin/sh

#********************************************************************
# Переменные
FTPCON="20:21" # Команды FTP
FTPDATA="49152:65535" # Данные FTP

# IP адреса
HOME="" # Admin's Home
ALIASWEB="159.69.214.219" # IP адрес интерфейса, на котором будут висеть сайты
#ALIASDNS="" # 2-ой IP адрес, чтобы нормально работал DNS
#ALIASLAN="" # IP в локалке (если есть)
ALIASLOOP="127.0.0.1" # IP LoopBack (замыкание на себя)

# Интерфейсы
INTWEB="eth0" # Название интерфейса, на котором будут висеть сайты
#INTDNS="" # Интефейс для DNS2
#INTLAN="" # Интерфейс локальной сети (если есть)
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

# Разрешаем исходящий трафик и запрещаем весь входящий и транзитный
$IPT -P INPUT DROP
$IPT -P OUTPUT ACCEPT
$IPT -P FORWARD DROP

# Разрешаем уже инициированные соединения, а также дочерние от них
$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

#Отбрасываем все пакеты, которые не могут быть идентифицированы
#и поэтому не могут иметь определенного статуса.
$IPT -A INPUT -m state --state INVALID -j DROP

# Запрет FIN-сканирования
#$IPT -A INPUT -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP

# Запрет X-сканирования
#$IPT -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP

# Запрет N-сканирования
#$IPT -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP

#
$IPT -A INPUT -p ALL -m state --state ESTABLISHED,RELATED -j ACCEPT # Дропаем битые пакеты, которые идут на вшнешний мир, если когда-нибуть будет NAT
$IPT -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j REJECT

#********************************************************************
# Цепочка syn-flood для обнаружения DDOS-атак
#$IPT -t mangle -N syn-flood
## Ограничение в 24 коннекта в сек., максимально разрешщено - 48
#$IPT -t mangle -A syn-flood -m limit --limit 24/s --limit-burst 48 -j RETURN
#$IPT -t mangle -A syn-flood \
    -m limit --limit 10/s  --limit-burst 10 -j LOG \
    --log-prefix "IPT: DDOS (dropped): "
#$IPT -t mangle -A syn-flood -j DROP
#********************************************************************

#********************************************************************
# Цепочка hack_scan для защиты от NMAP-сканирования
# Единственное от чего нет защиты, так это от "правильного сканирования", попытке реально подцепиться к порту
# т.е. от nmap -sS (Scan: SYN+ACK), а потом мониторить при помощи root-tail
#$IPT -t filter -N hack_scan
## nmap -sS (Скан: SYN+ACK = нет защиты... )
## nmap -sX (Скан: SYN+ACK+FIN+RST [+PSH+URG] = не реализовано в TCP)
#$IPT -t filter -A hack_scan -p tcp -m state ! --state ESTABLISHED \
#    --tcp-flags SYN,ACK,FIN,RST ALL  \
#    -j LOG --log-prefix "IPT: Scan: SYN+ACK+FIN+RST: " \
#    -m limit --limit 10/minute --limit-burst 10

#$IPT -t filter -A hack_scan -p tcp -m state ! --state ESTABLISHED \
#    --tcp-flags SYN,ACK,FIN,RST ALL  \
#    -j REJECT --reject-with tcp-reset

## nmap -sN (Скан: ни один из флагов = не реализовано в TCP)
#$IPT -t filter -A hack_scan -p tcp -m state ! --state ESTABLISHED \
#    --tcp-flags SYN,ACK,FIN,RST NONE \
#    -m limit --limit 10/minute --limit-burst 10 \
#    -j LOG --log-prefix "IPT: Scan: empty flags: "
#$IPT -t filter -A hack_scan -p tcp -m state ! --state ESTABLISHED \
#    --tcp-flags SYN,ACK,FIN,RST NONE \
#    -j REJECT --reject-with tcp-reset

## nmap -sF (Скан: только FIN)
#$IPT -t filter -A hack_scan -p tcp -m state ! --state ESTABLISHED \
#    --tcp-flags SYN,ACK,FIN,RST FIN \
#    -m limit --limit 10/minute --limit-burst 10 \
#    -j LOG --log-prefix "IPT: Scan: only FIN: "
#$IPT -t filter -A hack_scan -p tcp -m state ! --state ESTABLISHED \
#    --tcp-flags SYN,ACK,FIN,RST FIN \
#    -j REJECT --reject-with tcp-reset

## NEW, не SYN
#$IPT -t filter -A hack_scan -p tcp ! --syn -m state --state NEW \
#    -m limit --limit 10/minute --limit-burst 10 \
#    -j LOG --log-prefix "IPT: NEW not SYN (rejected): "
#$IPT -t filter -A hack_scan -p tcp ! --syn -m state --state NEW \
#    -j REJECT --reject-with tcp-reset
#********************************************************************=

#********************************************************************
# Защита ssh от перебора паролей
#$IPT -N FAILLOG
#$IPT -A FAILLOG -j LOG --log-prefix "iptables blocked: " --log-level 7
#$IPT -A FAILLOG -j DROP
#$IPT -A INPUT -p tcp -m tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 3 --name DEFAULT --rsource -j FAILLOG
#********************************************************************

# flooding of RST packets, smurf attack Rejection
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

# Protecting portscans
# Attacking IP will be locked for 24 hours (3600 x 24 = 86400 Seconds)
iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP

# Remove attacking IP after 24 hours
iptables -A INPUT -m recent --name portscan --remove
iptables -A FORWARD -m recent --name portscan --remove

# These rules add scanners to the portscan list, and log the attempt.
iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:"
iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:"
iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

#********************************************************************
# Разрешаем все для себя
$IPT -A INPUT -s $ALIASLOOP -d $ALIASLOOP -j ACCEPT
$IPT -A INPUT -s $ALIASWEB -d $ALIASWEB -j ACCEPT
#$IPT -A INPUT -s $ALIASLAN -d $ALIASLAN -j ACCEPT
#$IPT -A INPUT -s $ALIASDNS -d $ALIASDNS -j ACCEPT
#
#$IPT -A INPUT -p icmp --icmp-type 8 -m limit --limit 10/s --limit-burst 20 -j ACCEPT	# ICMP
#$IPT -A INPUT -p icmp --icmp-type 11 -m limit --limit 10/s --limit-burst 20 -j ACCEPT	# ICMP
#********************************************************************

#********************************************************************
# Разрешаем разные протоколы:
$IPT -A INPUT -i $INTWEB -p tcp --dport 22 -j ACCEPT			# Разрешаем SSH
$IPT -A INPUT -i $INTWEB -p tcp --dport 80 -j ACCEPT			# Разрешаем HTTP
$IPT -A INPUT -i $INTWEB -p tcp --dport 443 -j ACCEPT			# Разрешаем HTTPS
$IPT -A INPUT -i $INTWEB -p udp --dport 53 -j ACCEPT			# Разрешаем DNS
#$IPT -A INPUT -i $INTDNS -p udp --dport 53 -j ACCEPT 			# Разрешаем DNS
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
$IPT -A INPUT -p icmp --icmp-type destination-unreachable -j DROP
$IPT -A INPUT -p icmp --icmp-type source-quench -j DROP
$IPT -A INPUT -p icmp --icmp-type time-exceeded -j DROP

# Блокируем все остальное
$IPT -A INPUT -j DROP

#Вывод информации о состоянии таблиц
#route -n
#$IPT -L
$IPT -L -v -n
#$IPT -L -v -n -t nat
