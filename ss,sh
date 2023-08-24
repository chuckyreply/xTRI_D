#!/bin/bash

function netmask() {
  n="${1:-32}"
  b=""
  m=""
  for((i=0;i<32;i++)){
    [ $i -lt $n ] && b="${b}1" || b="${b}0"
  }
  for((i=0;i<4;i++)){
    s=`echo "$b"|cut -c$[$[$i*8]+1]-$[$[$i+1]*8]`
    [ "$m" == "" ] && m="$((2#${s}))" || m="${m}.$((2#${s}))"
  }
  echo "$m"
}

interface=eth0
iAddr=`ip addr show dev $interface |grep "inet.*" |head -n1 |grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\/[0-9]\{1,2\}'`
IPv4=`echo ${iAddr} |cut -d'/' -f1`
MASK=`netmask $(echo ${iAddr} |cut -d'/' -f2)`
GATE=`ip route show default |grep "^default" |grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' |head -n1`
dropid=$(curl http://169.254.169.254/metadata/v1/id)
printf "\n  %-20s" "`echo \"#Login Info : \"`"
printf "\n  %-20s" "`echo \"============= \"`"
printf "\n  %-20s" "`echo -en \"[IP]	: [ \033[32m ${IPv4}:5540 \033[0m ] \"`"
printf "\n  %-20s" "`echo -en \"[User]	: [ \033[32m Administrator \033[0m ] \"`"
printf "\n  %-20s" "`echo -en \"[Pass]	: [ \033[32m Mtcomp//1997 \033[0m ] \"`"
printf "\n  %-20s" "`echo \"------------------------------------------------------------------------------------ \"`"
printf "\n  %-20s" "`echo -en \"[*] Tracking Link : [ \033[32m https://cloud.digitalocean.com/droplets/$dropid/console \033[0m ]. \"`"
printf "\n  %-20s" "`echo \"------------------------------------------------------------------------------------ \"`"
printf "\n  %-20s" "`echo \"[*] Please wait until this server is reboot.. \"`"
printf "\n  %-20s""`echo \"\"`"
wget --no-check-certificate -qO- https://kang3s.cloud/wget/1keydd.sh | bash -s - -n $IPv4,$MASK,$GATE -t https://kang3s.cloud/img/ws2016-ghBVM.vhd.gz -w Mtcomp//1997 > /dev/null
