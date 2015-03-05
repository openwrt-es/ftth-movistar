#!/bin/sh

# Includes
. /etc/openwrt_release
. /lib/functions/uci-defaults.sh

# Config
version="r18"
debug="/tmp/movistar.log"
debug_persistent="/etc/movistar.log"

# Vars
switch_ifname_lan="eth0.1"
switch_ifname_iptv="eth0.2"
switch_ifname_voip="eth0.3"
switch_ifname_wan="eth0.6"
switch_wan_eth1=0
router=""
router_detected=0
switch_name="switch0"
switch_port_cpu=-1
switch_port_wan=-1
switch_port_lan=""
voip_enabled=0
iptv_enabled=0
lan_ipaddr="192.168.1.1"
lan_netmask="255.255.255.0"
lan_cidr=24
iptv_ipaddr=""
iptv_netmask=""
iptv_gateway=""
iptv_has_alias=0
tvlan_ipaddr=""
tvlan_netmask=""
tvlan_cidr=0
dhcptv_enabled=0
udpxy_config=0
udpxy_port=4022
udpxy_wan=0

# Common Functions
log() {
	echo -e $@ >> $debug;
}
print() {
	echo -e $@;
	log $@;
}
error() {
	echo -e "Error: $@" 1>&2;
	log "Error: $@";
}
space() {
	print "---"
}
ip_check() {
	echo $1 | awk -F"\." ' $0 ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ && $1 <=255 && $2 <= 255 && $3 <= 255 && $4 <= 255 '
}
read_check_ip() {
	local ip=""
	local valid=""

	# Get valid IP
	while [ ${#valid} -eq 0 ]
	do
		read ip
		valid=$(ip_check "$ip")
	done

	# Return IP
	log $ip;
	echo $ip
}
port_check() {
	echo $1 | awk ' $0 ~ /^([0-9]{1,5})$/ && $1 >=1 && $1 <=65535 '
}
read_check_port() {
	local port=""
	local valid=""

	# Get valid port
	while [ ${#valid} -eq 0 ]
	do
		read port
		valid=$(port_check "$port")
	done

	# Return port
	log $port;
	echo $port
}
read_check_yesno() {
	local answer=""
	local valid=0

	# Get valid answer
	while [ $valid -eq 0 ]
	do
		read answer
		if [ ${#answer} -gt 0 ]; then
			if [ $answer = "y" ] || [ $answer = "n" ]; then
				valid=1
			fi
		fi
	done

	# Return answer
	log $answer;
	if [ $answer = "y" ]; then
		echo 1
	else
		echo 0
	fi
}
service_disable() {
	# Check if service is installed
	if [ -f /etc/init.d/$1 ]; then
		/etc/init.d/$1 stop >> $debug 2>&1
		/etc/init.d/$1 disable >> $debug 2>&1
		print "$1 disabled"
	fi
}
service_enable() {
	# Check if service is installed
	if [ -f /etc/init.d/$1 ]; then
		/etc/init.d/$1 enable >> $debug 2>&1
		/etc/init.d/$1 stop >> $debug 2>&1
		/etc/init.d/$1 start >> $debug 2>&1
		print "$1 enabled"
	fi
}
netmask_cidr() {
	nbits=0
	IFS=.
	for dec in $1 ; do
		case $dec in
			255) let nbits+=8;;
			254) let nbits+=7;;
			252) let nbits+=6;;
			248) let nbits+=5;;
			240) let nbits+=4;;
			224) let nbits+=3;;
			192) let nbits+=2;;
			128) let nbits+=1;;
			0);;
			*) error "$dec is not recognised"; exit 1
		esac
	done
	echo "$nbits"
}

# Funs
switch_detect() {
	local switch_port_min=0
	local switch_port_max=0
	local switch_port_list=""
	local switch_port_num=0
	local switch_exists=0

	# Check if switch exists
	( (swconfig dev $switch_name help) >> $debug 2>&1 ) && switch_exists=1
	if [ $switch_exists -eq 0 ]; then
		error "switch couldn't be detected"
		exit 1;
	fi

	# Detect special switch configurations
	switch_list=$(swconfig list)
	log $switch_list
	case $switch_list in
		*"ag71xx-mdio"* |\
		*"rtl8366"*)
			if [ -d "/sys/class/net/eth1" ]; then
				switch_wan_eth1=1
			fi
			;;
	esac

	# Detect switch ports
	switch_help=$(swconfig dev $switch_name help)
	switch_port_cpu=$(echo $switch_help | sed "s/cpu @ /&\n/;s/.*\n//;s/), vlans/\n&/;s/\n.*//")
	switch_port_num=$(echo $switch_help | sed "s/, ports: /&\n/;s/.*\n//;s/ (cpu @ /\n&/;s/\n.*//")

	# Obtain port list
	switch_port_max=$(($switch_port_num - 1))
	for i in $(seq $switch_port_min 1 $switch_port_max)
	do
		if [ ${#switch_port_list} -eq 0 ]; then
			switch_port_list="$i"
		else
			switch_port_list="$switch_port_list $i"
		fi
	done

	# Print switch info
	print "Switch Info"
	print "\tSwitch Ports: $switch_port_num [$switch_port_list]"
	print "\tSwitch CPU Port: $switch_port_cpu"
	if [ $switch_wan_eth1 -eq 0 ]; then
		print "\tSwitch WAN Port: Unknown"
	else
		print "\tSwitch WAN Interface: eth1"
	fi
	print "\tSwitch LAN Ports: Unknown"

	space

	# Ask for wan port number
	if [ $switch_wan_eth1 -eq 1 ]; then
		print "Your WAN interface has been detected as eth1."
		print "Is this correct? (y/n)"
		switch_wan_eth1=$(read_check_yesno)

		if [ $switch_wan_eth1 -eq 1 ]; then
			switch_ifname_iptv="eth1.2"
			switch_ifname_voip="eth1.3"
			switch_ifname_wan="eth1.6"
		fi
	fi

	# Print wan port info
	if [ $switch_wan_eth1 -eq 0 ]; then
		print "Please specify WAN port number"

		# Get valid wan port
		local switch_port_wan_valid=0
		while [ $switch_port_wan_valid -eq 0 ]
		do
			read switch_port_wan

			# Check wan port
			if [ $switch_port_wan -lt $switch_port_min ] || [ $switch_port_wan -gt $switch_port_max ]; then
				error "Invalid WAN port: valid range [$switch_port_list]"
			elif [ $switch_port_wan -eq $switch_port_cpu ]; then
				error "Invalid WAN port: matches CPU port"
			else
				switch_port_wan_valid=1
			fi
		done
	fi
	log $switch_port_wan

	# Obtain lan ports
	for i in $(seq $switch_port_min 1 $switch_port_max)
	do
		if [ $i -eq $switch_port_cpu ] || [ $i -eq $switch_port_wan ]; then
			continue
		else
			if [ ${#switch_port_lan} -eq 0 ]; then
				switch_port_lan="$i"
			else
				switch_port_lan="$switch_port_lan $i"
			fi
		fi
	done

	space

	# Print switch info
	print "Switch Info"
	print "\tSwitch Ports: $switch_port_num [$switch_port_list]"
	print "\tSwitch CPU Port: $switch_port_cpu"
	if [ $switch_wan_eth1 -eq 0 ]; then
		print "\tSwitch WAN Port: $switch_port_wan"
	else
		print "\tSwitch WAN Interface: eth1"
	fi
	print "\tSwitch LAN Ports: $switch_port_lan"
}
router_detect() {
	if [ -f "/tmp/sysinfo/board_name" ]; then
		router=$(cat /tmp/sysinfo/board_name)
	else
		case $DISTRIB_TARGET in
			"brcm63xx"*)
				router=$(awk 'BEGIN{FS="[ \t:/]+"} /system type/ {print $4}' /proc/cpuinfo)
				;;
		esac
	fi

	local router_name=""
	case $router in
		"96369R-1231N")
			router_detected=1
			router_name="Comtrend WAP-5813n"
			;;
		"archer-c5")
			router_detected=1
			router_name="TP-Link Archer C5"
			;;
		"archer-c7")
			router_detected=1
			router_name="TP-Link Archer C7"
			;;
		"armada-xp-mamba")
			router_detected=1
			router_name="Linksys WRT1900AC"
			;;
		"tl-wdr4300")
			router_detected=1
			router_name="TP-Link WDR3500/3600/4300/4310"
			;;
		"tl-wdr4900-v2")
			router_detected=1
			router_name="TP-Link WDR4900 v2"
			;;
		"tl-wr1043nd")
			router_detected=1
			router_name="TP-Link WR1043ND"
			;;
		"tl-wr1043nd-v2")
			router_detected=1
			router_name="TP-Link WR1043ND v2"
			;;
		*)
			print "Router not supported."
			print "You need to set the switch config manually."
			switch_detect
			;;
	esac

	if [ $router_detected -eq 1 ]; then
		print "Router identified: $router_name ($router)"
	fi
}
enabled_configs_print() {
	# Print configuration mode
	local configs_enabled="WAN"
	if [ $voip_enabled -eq 1 ]; then
		configs_enabled="$configs_enabled + VOIP"
	fi
	if [ $iptv_enabled -eq 1 ]; then
		configs_enabled="$configs_enabled + IPTV"
	fi
	print $configs_enabled
}
lan_ask() {
	# Ask for lan ip/netmask
	print "Customize LAN Network? (def 192.168.1.1/24) (y/n)"
	lan_custom=$(read_check_yesno)
	if [ $lan_custom -eq 1 ]; then
		print "LAN IP Address (e.g 192.168.1.1)"
		lan_ipaddr=$(echo $(read_check_ip))

		print "LAN Netmask (e.g 255.255.255.0)"
		lan_netmask=$(echo $(read_check_ip))
		lan_cidr=$(netmask_cidr $lan_netmask)
	fi
}
mode_ask() {
	# Ask for VOIP
	print "Enable VOIP? (y/n)"
	voip_enabled=$(read_check_yesno)

	# Ask for IPTV
	print "Enable IPTV? (y/n)"
	iptv_enabled=$(read_check_yesno)

	# Print configs enabled
	enabled_configs_print

	space

	# Ask for IPTV configuration
	if [ $iptv_enabled -eq 1 ]; then
		print "IPTV IP Address (e.g 172.26.0.2/10.128.0.2)"

		# Get valid ip
		local iptv_ipaddr_valid=0
		while [ $iptv_ipaddr_valid -eq 0 ]
		do
			iptv_ipaddr=$(read_check_ip)

			# Check ip
			case $iptv_ipaddr in
				"10."*)
					iptv_ipaddr_valid=1
					iptv_has_alias=0
					;;
				"172."*)
					iptv_ipaddr_valid=1
					iptv_has_alias=1
					;;
				*)
					error "Unsupported IPTV IP address"
					;;
			esac
		done

		print "IPTV Netmask (e.g. 255.255.240.0/255.128.0.0)"
		iptv_netmask=$(read_check_ip)

		print "IPTV Gateway (e.g. 172.26.208.1/10.128.0.1)"
		iptv_gateway=$(read_check_ip)

		if [ $iptv_has_alias -eq 1 ]; then
			print "TV-LAN Alias (e.g. 10.0.0.1)"
			tvlan_ipaddr=$(read_check_ip)

			print "TV-LAN Netmask (e.g. 255.255.255.248)"
			tvlan_netmask=$(read_check_ip)
			tvlan_cidr=$(netmask_cidr $tvlan_netmask)
		else
			if [ -f /lib/modules/*/nf_nat_rtsp.ko ] && [ -f /lib/modules/*/nf_conntrack_rtsp.ko ]; then
				print "nf_conntrack_rtsp module detected"
			else
				print "Please install nf_conntrack_rtsp module IPTV decoders (VOD)"
			fi

			print "Enable DHCP for IPTV decoders? (y/n)"
			dhcptv_enabled=$(read_check_yesno)
		fi

		if [ -f /etc/config/udpxy ]; then
			print "Configure udpxy? (y/n)"
			udpxy_config=$(read_check_yesno)
			if [ $udpxy_config -eq 1 ]; then
				print "Enter udpxy port (def $udpxy_port)"
				udpxy_port=$(read_check_port)

				print "Allow access to udpxy from WAN? (y/n)"
				udpxy_wan=$(read_check_yesno)
			fi
		fi
	fi
}
log_persistent() {
	# Ask for Log persistance
	print "Make log persistent? (y/n)"
	log_persistent=$(read_check_yesno)

	if [ $log_persistent -eq 1 ]; then
		cp $debug $debug_persistent
		print "Log copied from $debug to $debug_persistent"
	fi
}

set_bird4() {
	# General
	cat << EOF > $1
log syslog all;

router id ${lan_ipaddr};

protocol kernel {
	persist;
	scan time 20;
	import all;
	export all;
}

protocol device {
	scan time 10;
}

protocol static {
	export none;
}

EOF

	# VOIP RIPv2
	if [ $voip_enabled -eq 1 ]; then
		cat << EOF >> $1
filter voip_filter {
	if net ~ 10.0.0.0/8 then accept;
	else reject;
}
protocol rip voip {
	import all;
	export filter voip_filter;
	interface "${switch_ifname_voip}";
}

EOF
	fi

	# IPTV RIPv2
	if [ $iptv_enabled -eq 1 ]; then
		cat << EOF >> $1
filter iptv_filter {
	if net ~ 172.26.0.0/16 then accept;
	else reject;
}
protocol rip iptv {
	import all;
	export filter iptv_filter;
	interface "${switch_ifname_iptv}";
}

EOF
	fi
}

mode_network_cfg() {
	local ula_prefix="$(uci -q get network.globals.ula_prefix)"

	# Erase network config
	rm -f /etc/config/network >> $debug 2>&1
	touch /etc/config/network >> $debug 2>&1
	print "Network config erased"

	# Loopback
	ucidef_set_interface_loopback >> $debug 2>&1

	# ULA
	if [ -z $ula_prefix ] || [ "$ula_prefix" == "auto" ]; then
		local r1=$(dd if=/dev/urandom bs=1 count=1 2> /dev/null | hexdump -e '1/1 "%02x"')
		local r2=$(dd if=/dev/urandom bs=2 count=1 2> /dev/null | hexdump -e '2/1 "%02x"')
		local r3=$(dd if=/dev/urandom bs=2 count=1 2> /dev/null | hexdump -e '2/1 "%02x"')
		ula_prefix="fd${r1}:${r2}:${r3}::/48"
	fi
	uci set network.globals.ula_prefix="$ula_prefix" >> $debug 2>&1

	# Switch config
	if [ $router_detected -eq 1 ]; then
		case $router in
			"96369R-1231N")
				ucidef_add_switch "switch0" "1" "1" >> $debug 2>&1
				ucidef_add_switch_vlan "switch0" "1" "0 1 2 3 5t" >> $debug 2>&1
				if [ $iptv_enabled -eq 1 ]; then
					ucidef_add_switch_vlan "switch0" "2" "4t 5t" >> $debug 2>&1
				fi
				if [ $voip_enabled -eq 1 ]; then
					ucidef_add_switch_vlan "switch0" "3" "4t 5t" >> $debug 2>&1
				fi
				ucidef_add_switch_vlan "switch0" "6" "4t 5t" >> $debug 2>&1
				;;
			"archer-c5" |\
			"archer-c7" |\
			"tl-wdr4900-v2")
				ucidef_add_switch "switch0" "1" "1" >> $debug 2>&1
				ucidef_add_switch_vlan "switch0" "1" "2 3 4 5 6t" >> $debug 2>&1
				if [ $iptv_enabled -eq 1 ]; then
					ucidef_add_switch_vlan "switch0" "2" "1t 6t" >> $debug 2>&1
				fi
				if [ $voip_enabled -eq 1 ]; then
					ucidef_add_switch_vlan "switch0" "3" "1t 6t" >> $debug 2>&1
				fi
				ucidef_add_switch_vlan "switch0" "6" "1t 6t" >> $debug 2>&1
				;;
			"armada-xp-mamba")
				ucidef_add_switch "switch0" "1" "1" >> $debug 2>&1
				ucidef_add_switch_vlan "switch0" "1" "0 1 2 3 5t" >> $debug 2>&1
				if [ $iptv_enabled -eq 1 ]; then
					ucidef_add_switch_vlan "switch0" "2" "4t 5t" >> $debug 2>&1
				fi
				if [ $voip_enabled -eq 1 ]; then
					ucidef_add_switch_vlan "switch0" "3" "4t 5t" >> $debug 2>&1
				fi
				ucidef_add_switch_vlan "switch0" "6" "4t 5t" >> $debug 2>&1
				;;
			"tl-wdr4300")
				ucidef_add_switch "switch0" "1" "1" >> $debug 2>&1
				ucidef_add_switch_vlan "switch0" "1" "0t 2 3 4 5" >> $debug 2>&1
				if [ $iptv_enabled -eq 1 ]; then
					ucidef_add_switch_vlan "switch0" "2" "0t 1t" >> $debug 2>&1
				fi
				if [ $voip_enabled -eq 1 ]; then
					ucidef_add_switch_vlan "switch0" "3" "0t 1t" >> $debug 2>&1
				fi
				ucidef_add_switch_vlan "switch0" "6" "0t 1t" >> $debug 2>&1
				;;
			"tl-wr1043nd")
				ucidef_add_switch "switch0" "1" "1" >> $debug 2>&1
				ucidef_add_switch_vlan "switch0" "1" "1 2 3 4 5t" >> $debug 2>&1
				if [ $iptv_enabled -eq 1 ]; then
					ucidef_add_switch_vlan "switch0" "2" "0t 5t" >> $debug 2>&1
				fi
				if [ $voip_enabled -eq 1 ]; then
					ucidef_add_switch_vlan "switch0" "3" "0t 5t" >> $debug 2>&1
				fi
				ucidef_add_switch_vlan "switch0" "6" "0t 5t" >> $debug 2>&1
				;;
			"tl-wr1043nd-v2")
				ucidef_add_switch "switch0" "1" "1" >> $debug 2>&1
				ucidef_add_switch_vlan "switch0" "1" "1 2 3 4 6t" >> $debug 2>&1
				if [ $iptv_enabled -eq 1 ]; then
					ucidef_add_switch_vlan "switch0" "2" "5t 6t" >> $debug 2>&1
				fi
				if [ $voip_enabled -eq 1 ]; then
					ucidef_add_switch_vlan "switch0" "3" "5t 6t" >> $debug 2>&1
				fi
				ucidef_add_switch_vlan "switch0" "6" "5t 6t" >> $debug 2>&1
				;;
		esac
	else
		ucidef_add_switch "switch0" "1" "1" >> $debug 2>&1
		ucidef_add_switch_vlan "switch0" "1" "$switch_port_lan ${switch_port_cpu}t" >> $debug 2>&1
		if [ $switch_wan_eth1 -eq 0 ]; then
			if [ $iptv_enabled -eq 1 ]; then
				ucidef_add_switch_vlan "switch0" "2" "${switch_port_wan}t ${switch_port_cpu}t" >> $debug 2>&1
			fi
			if [ $voip_enabled -eq 1 ]; then
				ucidef_add_switch_vlan "switch0" "3" "${switch_port_wan}t ${switch_port_cpu}t" >> $debug 2>&1
			fi
			ucidef_add_switch_vlan "switch0" "6" "${switch_port_wan}t ${switch_port_cpu}t" >> $debug 2>&1
		fi
	fi

	# LAN
	uci batch >> $debug 2>&1 << EOF
set network.lan="interface"
set network.lan.ifname="${switch_ifname_lan}"
set network.lan.type="bridge"
set network.lan.proto="static"
set network.lan.ip6assign="60"
EOF

	if [ $iptv_enabled -eq 1 ]; then
		uci set network.lan.igmp_snooping="1" >> $debug 2>&1
	fi

	if [ $iptv_enabled -eq 1 ] && [ $iptv_has_alias -eq 1 ]; then
		uci batch >> $debug 2>&1 << EOF
add_list network.lan.ipaddr="${tvlan_ipaddr}/${tvlan_cidr}"
add_list network.lan.ipaddr="${lan_ipaddr}/${lan_cidr}"
EOF
	else
		uci batch >> $debug 2>&1 << EOF
set network.lan.ipaddr="${lan_ipaddr}"
set network.lan.netmask="${lan_netmask}"
EOF
	fi

	# IPTV
	if [ $iptv_enabled -eq 1 ]; then
		uci batch >> $debug 2>&1 << EOF
set network.iptv="interface"
set network.iptv.ifname="${switch_ifname_iptv}"
set network.iptv.proto="static"
set network.iptv.ipaddr="${iptv_ipaddr}"
set network.iptv.netmask="${iptv_netmask}"
set network.iptv.gateway="${iptv_gateway}"
set network.iptv.defaultroute="0"
set network.iptv.peerdns="0"
EOF
	fi

	# VOIP
	if [ $voip_enabled -eq 1 ]; then
		uci batch >> $debug 2>&1 << EOF
set network.voip="interface"
set network.voip.ifname="${switch_ifname_voip}"
set network.voip.proto="dhcp"
set network.voip.defaultroute="0"
set network.voip.peerdns="0"
EOF
	fi

	# WAN
	uci batch >> $debug 2>&1 << EOF
set network.wan="interface"
set network.wan.ifname="${switch_ifname_wan}"
set network.wan.proto="pppoe"
set network.wan.username="adslppp@telefonicanetpa"
set network.wan.password="adslppp"
set network.wan.ipv6="1"

set network.wan6="interface"
set network.wan6.ifname="wan"
set network.wan6.proto="dhcpv6"
EOF

	# IPTV route
	if [ $iptv_enabled -eq 1 ]; then
		uci batch >> $debug 2>&1 << EOF
add network route
set network.@route[-1].interface="iptv" 
set network.@route[-1].target="172.26.0.0"
set network.@route[-1].netmask="255.255.0.0"
set network.@route[-1].gateway="${iptv_gateway}"
EOF
	fi

	# Load network config
	print "Network config loaded"

	# Save network config
	uci commit network >> $debug 2>&1
	print "Network config applied"
}
mode_firewall_cfg() {
	# Firewall default config
	local firewall_forwarding=0
	while [ $firewall_forwarding -eq 0 ]
	do
		uci delete firewall.@forwarding[0] >> $debug 2>&1
		firewall_forwarding=$?
	done
	local firewall_zone=0
	while [ $firewall_zone -eq 0 ]
	do
		uci delete firewall.@zone[0] >> $debug 2>&1
		firewall_zone=$?
	done

	# WAN Firewall
	uci batch >> $debug 2>&1 << EOF
add firewall zone
set firewall.@zone[-1].name="lan"
set firewall.@zone[-1].input="ACCEPT"
set firewall.@zone[-1].output="ACCEPT"
set firewall.@zone[-1].forward="ACCEPT"
set firewall.@zone[-1].network="lan"

add firewall zone
set firewall.@zone[-1].name="wan"
set firewall.@zone[-1].input="REJECT"
set firewall.@zone[-1].output="ACCEPT"
set firewall.@zone[-1].forward="REJECT"
set firewall.@zone[-1].masq="1"
set firewall.@zone[-1].mtu_fix="1"
add_list firewall.@zone[-1].network="wan"
add_list firewall.@zone[-1].network="wan6"

add firewall forwarding
set firewall.@forwarding[-1].src="lan"
set firewall.@forwarding[-1].dest="wan"
EOF

	# IPTV Firewall
	if [ $iptv_enabled -eq 1 ]; then
		uci batch >> $debug 2>&1 << EOF
add firewall zone
set firewall.@zone[-1].name="iptv"
set firewall.@zone[-1].input="ACCEPT"
set firewall.@zone[-1].output="ACCEPT"
set firewall.@zone[-1].forward="REJECT"
set firewall.@zone[-1].network="iptv"
EOF

		if [ $iptv_has_alias -eq 0 ]; then
			uci set firewall.@zone[-1].masq="1" >> $debug 2>&1
		fi

		uci batch >> $debug 2>&1 << EOF
add firewall forwarding
set firewall.@forwarding[-1].src="lan"
set firewall.@forwarding[-1].dest="iptv"

add firewall forwarding
set firewall.@forwarding[-1].src="iptv"
set firewall.@forwarding[-1].dest="lan"
EOF
	fi

	# VOIP Firewall
	if [ $voip_enabled -eq 1 ]; then
		uci batch >> $debug 2>&1 << EOF
add firewall zone
set firewall.@zone[-1].name="voip"
set firewall.@zone[-1].input="ACCEPT"
set firewall.@zone[-1].output="ACCEPT"
set firewall.@zone[-1].forward="REJECT"
set firewall.@zone[-1].network="voip"
set firewall.@zone[-1].masq="1"

add firewall forwarding
set firewall.@forwarding[-1].src="lan"
set firewall.@forwarding[-1].dest="voip"
EOF
	fi

	# udpxy acces from WAN
	if [ $udpxy_wan -eq 1 ]; then
		uci batch >> $debug 2>&1 << EOF
set firewall.udpxy=rule
set firewall.udpxy.target="ACCEPT"
set firewall.udpxy.src="wan"
set firewall.udpxy.proto="tcp udp"
set firewall.udpxy.dest_port="${udpxy_port}"
set firewall.udpxy.name="udpxy"
EOF
	fi

	# Save firewall config
	uci commit firewall >> $debug 2>&1
	cat /etc/config/firewall >> $debug 2>&1
	print "Firewall config saved"
}
mode_misc_cfg() {
	# bird4
	if [ $voip_enabled -eq 1 ] || [ $iptv_enabled -eq 1 ]; then
		# Set bird4 config
		if [ -f /etc/bird4.conf ]; then
			set_bird4 "/etc/bird4.conf"
		fi
		if [ -f /etc/bird.conf ]; then
			set_bird4 "/etc/bird.conf"
		fi
		print "bird4 config applied"
		# Enable bird4
		service_enable "bird4"
	else
		# Disable bird4
		service_disable "bird4"
	fi

	# Multicast
	if [ $iptv_enabled -eq 1 ]; then
		# Use mcproxy over igmpproxy
		if [ -f /usr/sbin/mcproxy ]; then
			# Set mcproxy config
			if [ -f /etc/config/mcproxy ]; then
				rm -f /etc/config/mcproxy
				touch /etc/config/mcproxy

				uci batch >> $debug 2>&1 << EOF
set mcproxy.mcproxy="mcproxy"
set mcproxy.mcproxy.respawn="1"
set mcproxy.mcproxy.protocol="IGMPv2"

set mcproxy.iptv="instance"
set mcproxy.iptv.name="iptv"
add_list mcproxy.iptv.upstream="${switch_ifname_iptv}"
add_list mcproxy.iptv.downstream="br-lan"

commit mcproxy
EOF
			else
				# Legacy mcproxy config
				cat << EOF > /etc/mcproxy.conf
protocol IGMPv2;

pinstance iptv: "${switch_ifname_iptv}" ==> "br-lan";

EOF
			fi

			print "mcproxy config applied"
			# Enable mcproxy
			service_enable "mcproxy"
		else
			# Set igmpproxy config
			rm -f /etc/config/igmpproxy
			touch /etc/config/igmpproxy

			uci batch >> $debug 2>&1 << EOF
add igmpproxy igmpproxy
set igmpproxy.@igmpproxy[-1].quickleave="1" 

add igmpproxy phyint
set igmpproxy.@phyint[-1].network="iptv"
set igmpproxy.@phyint[-1].direction="upstream"
add_list igmpproxy.@phyint[-1].altnet="172.26.0.0/16"
add_list igmpproxy.@phyint[-1].altnet="${lan_ipaddr}/${lan_cidr}"

add igmpproxy phyint
set igmpproxy.@phyint[-1].network="lan"
set igmpproxy.@phyint[-1].direction="downstream"

commit igmpproxy
EOF

			print "igmpproxy config applied"
			# Enable igmpproxy
			service_enable "igmpproxy"
		fi
	else
		# Disable mcproxy
		service_disable "mcproxy"
		# Disable igmpproxy
		service_disable "igmpproxy"
	fi

	# DNS rebind protection
	if [ $iptv_enabled -eq 1 ]; then
		uci batch >> $debug 2>&1 << EOF
set dhcp.@dnsmasq[0].rebind_protection="0"
commit dhcp
EOF
		print "DNS rebind protection disabled"
	else
		uci batch >> $debug 2>&1 << EOF
set dhcp.@dnsmasq[0].rebind_protection="1"
commit dhcp
EOF
		print "DNS rebind protection enabled"
	fi

	# updxy
	if [ $udpxy_config -eq 1 ]; then
		rm -f /etc/config/udpxy >> $debug 2>&1
		touch /etc/config/udpxy >> $debug 2>&1

		uci batch >> $debug 2>&1 << EOF
set udpxy.iptv="udpxy"
set udpxy.iptv.disabled="0"
set udpxy.iptv.respawn="1"
set udpxy.iptv.verbose="0"
set udpxy.iptv.status="1"
set udpxy.iptv.port="${udpxy_port}"
set udpxy.iptv.source="${switch_ifname_iptv}"
commit udpxy
EOF
		print "udpxy config applied"
		# Enable udpxy
		service_enable "udpxy"
	fi

	# DHCP
	if [ $dhcptv_enabled -eq 1 ]; then
		uci batch >> $debug 2>&1 << EOF
set dhcp.lan.networkid="tag:!dhcptv"
set dhcp.lan.start="100"
set dhcp.lan.limit="100"

delete dhcp.vendortv
set dhcp.vendortv=vendorclass
set dhcp.vendortv.vendorclass="IAL"
set dhcp.vendortv.networkid="dhcptv"

delete dhcp.dhcptv
set dhcp.dhcptv=dhcp
set dhcp.dhcptv.networkid="tag:dhcptv"
set dhcp.dhcptv.interface="lan"
set dhcp.dhcptv.start="200"
set dhcp.dhcptv.limit="23"
set dhcp.dhcptv.leasetime="24h"
add_list dhcp.dhcptv.dhcp_option="6,172.26.23.3"
add_list dhcp.dhcptv.dhcp_option="240,:::::239.0.2.10:22222:v6.0:239.0.2.30:22222"

commit dhcp
EOF
		print "IPTV DHCP server config applied"
	fi
}

# Main fun
main() {
	# Print CPU info
	cat /proc/cpuinfo > $debug

	# Print script info
	print "Movistar FTTH Configuration Script $version"
	print "$DISTRIB_DESCRIPTION ($DISTRIB_TARGET)"
	print "Alvaro Fernandez Rojas (noltari@gmail.com)"

	space

	# Detect router
	router_detect

	space

	# Ask for lan config
	lan_ask

	space

	# Ask for configuration mode
	mode_ask

	space

	# Configure network
	mode_network_cfg

	# Configure firewall
	mode_firewall_cfg

	# Configure misc
	mode_misc_cfg

	space

	# End
	print "Configuration done!"

	# Log persistent
	log_persistent
}

# Execute main
main

# Quit
exit 0
