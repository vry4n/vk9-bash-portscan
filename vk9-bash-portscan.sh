#!/bin/bash
# Author: Bryan Alfaro (Vry4n)
# Date: 10/10/20
# Site: https://vk9-sec.com
# Description: A basic port scan tool
# Usage: ./vk9-bash-portscan.sh {port} {IP}/{mask}
# example 1: ./vk9-bash-portscan.sh any 192.168.0.0/24 tcp
# example 2: ./vk9-bash-portscan.sh 22,23 192.168.0.1 any

function banner {
  echo "__     ___  _____    ____                       _ _         "
  echo "\ \   / / |/ / _ \  / ___|  ___  ___ _   _ _ __(_) |_ _   _ "
  echo " \ \ / /| ' / (_) | \___ \ / _ \/ __| | | | '__| | __| | | |"
  echo "  \ V / |  . \\__, |  ___) |  __/ (__| |_| | |  | | |_| |_| |"
  echo "   \_/  |_|\_\ /_/  |____/ \___|\___|\__,_|_|  |_|\__|\__, |"
  echo "                        By Vry4n                      |___/ "
  echo "               ==========================                   "
}

# Values that the script needs to run
PORT=$1
IP=$2
proto=$3
# includes de ports
array_var=()
IPs=()

# A list of subnets added into an associative array
declare -A subnet_list
subnet_list["32"]="255.255.255.255"
subnet_list["31"]="255.255.255.254"
subnet_list["30"]="255.255.255.252"
subnet_list["29"]="255.255.255.248"
subnet_list["28"]="255.255.255.240"
subnet_list["27"]="255.255.255.224"
subnet_list["26"]="255.255.255.192"
subnet_list["25"]="255.255.255.128"
subnet_list["24"]="255.255.255.0"
subnet_list["23"]="255.255.254.0"
subnet_list["22"]="255.255.252.0"
subnet_list["21"]="255.255.248.0"
subnet_list["20"]="255.255.240.0"
subnet_list["19"]="255.255.224.0"
subnet_list["18"]="255.255.192.0"
subnet_list["17"]="255.255.128.0"
subnet_list["16"]="255.255.0.0"
subnet_list["15"]="255.254.0.0"
subnet_list["14"]="255.252.0.0"
subnet_list["13"]="255.248.0.0"
subnet_list["12"]="255.240.0.0"
subnet_list["11"]="255.224.0.0"
subnet_list["10"]="255.192.0.0"
subnet_list["9"]="255.128.0.0"
subnet_list["8"]="255.0.0.0"

#This function will set an array with each port listed. Depending on the input the case switch will execute
function get_ports {
	case $PORT in
		any)
			TYPE=any
			PORTS=$(seq 1 65535)
			for i in $PORTS
			do
				array_var+=($i)
			done
			;;
		[0-9]*,[0-9]*)
			TYPE=range
			PORTS=$(tr "," "\n" <<< $PORT)
			for i in $PORTS
			do
				array_var+=($i)
			done
			;;
		[0-9]*)
			TYPE=single
			PORTS=$PORT
			array_var+=$PORTS
			;;
	esac
}

# Separates the IP and the mask into an array from 192.168.0.0/24 to 192.168.0.0 24
function get_mask {
	case $IP in
		[0-9]*\.[0-9]*\.[0-9]*\.[0-9])
			IPs+=($IP)
			IPs+=("32")
			;;
		[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*/[0-9]*)
			IP_MASK=$(tr "/" "\n" <<< $IP)
			for i in $IP_MASK
			do
				 IPs+=($i)
			done
			;;
	esac
}

# This function will return the address space based on the mask (Start - End IP)
function get_subnet {
	IFS=. read -r i1 i2 i3 i4 <<< "${IPs[0]}"
	IFS=. read -r m1 m2 m3 m4 <<< "${subnet_list["${IPs[1]}"]}"

	network="$((i1 & m1)).$((i2 & m2)).$((i3 & m3)).$((i4 & m4))"
	broadcast="$((i1 & m1 | 255-m1)).$((i2 & m2 | 255-m2)).$((i3 & m3 | 255-m3)).$((i4 & m4 | 255-m4))"
	first_IP="$((i1 & m1)).$((i2 & m2)).$((i3 & m3)).$(((i4 & m4)))"
	last_IP="$((i1 & m1 | 255-m1)).$((i2 & m2 | 255-m2)).$((i3 & m3 | 255-m3)).$(((i4 & m4 | 255-m4)))"
}

# This is the TCP port scanner
function engine_tcp {
	$(ping -c2 ${targetIP} >/dev/null 2>&1)
	if [ "$?" = 0 ]; then
		echo "========IP==========="
		echo "| $targetIP is UP |"
		echo "=======PORTS========="
		for i in ${PORTS}; do
			$(nc -vz -w 1 -n $targetIP $i)
			if [ "$?" = 0 ]; then
				echo "| $i/TCP is UP"
			else
				continue
			fi
		done
	echo "_____________________"
	fi
}

# This gets all the IPs for the TCP engine to run the scan
function tcp_scan {
	# This would make the desition to which IPs should be scanned
	if [ ${IPs[1]} -ge 24 ] && [ ${IPs[1]} -le 32 ]; then
		start=$(awk -F"." '{print $4}' <<< ${first_IP})
		last=$(awk -F"." '{print $4}' <<< ${last_IP})
		for i in $(seq $start $last); do
			target=$(cut -d"." -f1-3 <<< ${network})
			dot="."
			targetIP=$target$dot$i
			engine_tcp
		done
	elif [ ${IPs[1]} -ge 16 ] && [ ${IPs[1]} -le 24 ]; then
		start1=$(awk -F"." '{print $4}' <<< ${first_IP})
		last1=$(awk -F"." '{print $4}' <<< ${last_IP})
		start2=$(awk -F"." '{print $3}' <<< ${first_IP})
		last2=$(awk -F"." '{print $3}' <<< ${last_IP})
		for i in $(seq $start2 $last2); do
			target=$(cut -d"." -f1-2 <<< ${network})
			dot="."
			targetIP=$target$dot$i$dot
			for j in $targetIP; do
				for k in $(seq $start1 $last1); do
						targetIP=$j$k
						engine_tcp
				done
			done
		done
	elif [ ${IPs[1]} -ge 8 ] && [ ${IPs[1]} -le 16 ]; then
		start1=$(awk -F"." '{print $4}' <<< ${first_IP})
		last1=$(awk -F"." '{print $4}' <<< ${last_IP})
		start2=$(awk -F"." '{print $3}' <<< ${first_IP})
		last2=$(awk -F"." '{print $3}' <<< ${last_IP})
		start3=$(awk -F"." '{print $2}' <<< ${first_IP})
		last3=$(awk -F"." '{print $2}' <<< ${last_IP})
		for x in $(seq $start3 $last3); do
			target=$(cut -d"." -f1-1 <<< ${network})
			dot="."
			targetIP=$target$dot$x$dot
			for i in $targetIP; do
				for j in $(seq $start2 $last2); do
					targetIP=$i$j$dot
					for l in $targetIP; do
						for z in $(seq $start1 $last1); do
							targetIP=$l$z
							engine_tcp
						done
					done
				done
			done
		done
	fi
}

# This is the UDP port scanner
function engine_udp {
	$(ping -c2 ${targetIP} >/dev/null 2>&1)
	if [ "$?" = 0 ]; then
		echo "========IP==========="
		echo "| $targetIP is UP |"
		echo "=======PORTS========="
		for i in ${PORTS}; do
			$(nc -vz -u -w 1 -n $targetIP $i)
			if [ "$?" = 0 ]; then
				echo "| $i/UDP is UP"
			else
				continue
			fi
		done
	echo "_____________________"
	fi
}

# This gets all the IPs for the UDP engine to run the scan
function udp_scan {
	# This would make the desition to which IPs should be scanned
	if [ ${IPs[1]} -ge 24 ] && [ ${IPs[1]} -le 32 ]; then
		start=$(awk -F"." '{print $4}' <<< ${first_IP})
		last=$(awk -F"." '{print $4}' <<< ${last_IP})
		for i in $(seq $start $last); do
			target=$(cut -d"." -f1-3 <<< ${network})
			dot="."
			targetIP=$target$dot$i
			engine_udp
		done
	elif [ ${IPs[1]} -ge 16 ] && [ ${IPs[1]} -le 24 ]; then
		start1=$(awk -F"." '{print $4}' <<< ${first_IP})
		last1=$(awk -F"." '{print $4}' <<< ${last_IP})
		start2=$(awk -F"." '{print $3}' <<< ${first_IP})
		last2=$(awk -F"." '{print $3}' <<< ${last_IP})
		for i in $(seq $start2 $last2); do
			target=$(cut -d"." -f1-2 <<< ${network})
			dot="."
			targetIP=$target$dot$i$dot
			for j in $targetIP; do
				for k in $(seq $start1 $last1); do
						targetIP=$j$k
						engine_udp
				done
			done
		done
	elif [ ${IPs[1]} -ge 8 ] && [ ${IPs[1]} -le 16 ]; then
		start1=$(awk -F"." '{print $4}' <<< ${first_IP})
		last1=$(awk -F"." '{print $4}' <<< ${last_IP})
		start2=$(awk -F"." '{print $3}' <<< ${first_IP})
		last2=$(awk -F"." '{print $3}' <<< ${last_IP})
		start3=$(awk -F"." '{print $2}' <<< ${first_IP})
		last3=$(awk -F"." '{print $2}' <<< ${last_IP})
		for x in $(seq $start3 $last3); do
			target=$(cut -d"." -f1-1 <<< ${network})
			dot="."
			targetIP=$target$dot$x$dot
			for i in $targetIP; do
				for j in $(seq $start2 $last2); do
					targetIP=$i$j$dot
					for l in $targetIP; do
						for z in $(seq $start1 $last1); do
							targetIP=$l$z
							echo $targetIP
							engine_udp
						done
					done
				done
			done
		done
	fi
}

# Main function
function main {
	banner
	# running the functions previously created so we gathered Ports, IP ranges, Subnet value
	get_ports
	get_mask
	get_subnet
	if [ $proto = "tcp" ]; then
		tcp_scan
	elif [ $proto = "udp" ]; then
		udp_scan
	else
	tcp_scan
	udp_scan
	fi

}

main
