#!/bin/sh

# Includes
. /etc/openwrt_release
. /lib/functions/uci-defaults.sh

# Config
version="r7"
debug=0
vlan_tagged_port="t"

# Vars
switch_ifname="eth0"
switch_name="switch0"
switch_port_min=0
switch_port_max=0
switch_port_list=""
switch_port_num=0
switch_port_cpu=-1
switch_port_wan=-1
switch_port_lan=""
voip_enabled=0
iptv_enabled=0
iptv_ipaddr=""
iptv_netmask=""
iptv_gateway=""
iptv_has_alias=0
tvlan_ipaddr=""
tvlan_netmask=""
deco_enabled=0
deco_ipaddr=""

# Common Functions
print() {
	echo -e $@;
}
debug() {
	if [[ $debug -gt 0 ]]; then
		echo -e $@;
	fi
}
error() {
	echo -e "Error: " "$@" 1>&2;
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
	while [[ ${#valid} -eq 0 ]]
	do
		read ip
		valid=$(ip_check "$ip")
	done

	# Return IP
	echo $ip
}
read_check_yesno() {
	local answer=""
	local valid=0

	# Get valid answer
	while [[ $valid -eq 0 ]]
	do
		read answer
		if [[ ${#answer} -gt 0 ]]; then
			if [[ $answer == "y" || $answer == "n" ]]; then
				valid=1
			fi
		fi
	done

	# Return answer
	if [[ $answer == "y" ]]; then
		echo 1
	else
		echo 0
	fi
}
service_disable() {
	# Check if service is installed
	if [ -f /etc/init.d/$1 ]; then
		/etc/init.d/$1 stop
		/etc/init.d/$1 disable
		print "$1 disabled"
	fi
}
service_enable() {
	# Check if service is installed
	if [ -f /etc/init.d/$1 ]; then
		/etc/init.d/$1 enable
		/etc/init.d/$1 stop
		/etc/init.d/$1 start
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
			*) echo "Error: $dec is not recognised"; exit 1
		esac
	done
	echo "$nbits"
}

# Funs
switch_detect() {
	# Check if switch0 exists
	switch_exists=0
	( (swconfig dev $switch_name help) &> /dev/null ) && switch_exists=1
	if [[ $switch_exists -eq 0 ]]; then
		error "switch couldn't be detected"
		exit 1;
	fi

	# Detect switch ports
	switch_help=$(swconfig dev $switch_name help)
	switch_port_cpu=$(echo $switch_help | sed "s/cpu @ /&\n/;s/.*\n//;s/), vlans/\n&/;s/\n.*//")
	switch_port_num=$(echo $switch_help | sed "s/, ports: /&\n/;s/.*\n//;s/ (cpu @ /\n&/;s/\n.*//")

	# Obtain port list
	switch_port_max=$(($switch_port_num - 1))
	for i in $(seq $switch_port_min 1 $switch_port_max)
	do
		if [[ ${#switch_port_list} -eq 0 ]]; then
			switch_port_list="$i"
		else
			switch_port_list="$switch_port_list $i"
		fi
	done
}
wan_port_ask() {
	# Print wan port info
	print "Please specify WAN port number"
	read switch_port_wan

	# Check port
	if [[ $switch_port_wan -lt $switch_port_min || $switch_port_wan -gt $switch_port_max ]]; then
		error "Invalid WAN port: valid range [$switch_port_list]"
		wan_port_ask
	fi
	if [[ $switch_port_wan -eq $switch_port_cpu ]]; then
		error "Invalid WAN port: matches CPU port"
		wan_port_ask
	fi

	# Obtain lan ports
	for i in $(seq $switch_port_min 1 $switch_port_max)
	do
		if [[ $i -eq $switch_port_cpu ]] || [[ $i -eq $switch_port_wan ]]; then
			continue
		else
			if [[ ${#switch_port_lan} -eq 0 ]]; then
				switch_port_lan="$i"
			else
				switch_port_lan="$switch_port_lan $i"
			fi
		fi
	done
}
enabled_configs_print() {
	# Print configuration mode
	local configs_enabled="WAN"
	if [[ $voip_enabled -eq 1 ]]; then
		configs_enabled="$configs_enabled + VOIP"
	fi
	if [[ $iptv_enabled -eq 1 ]]; then
		configs_enabled="$configs_enabled + IPTV"
	fi
	print $configs_enabled
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
	if [[ $iptv_enabled -eq 1 ]]; then
		print "IPTV IP Address (e.g 172.26.0.2/10.128.0.2)"
		iptv_ipaddr=$(read_check_ip)

		case $iptv_ipaddr in
			"10."*)
				iptv_has_alias=0
				;;
			"172."*)
				iptv_has_alias=1
				;;
			*)
				error "Unsupported IPTV IP address"
				mode_ask
				;;
		esac

		print "IPTV Netmask (e.g. 255.255.240.0/255.128.0.0)"
		iptv_netmask=$(read_check_ip)

		print "IPTV Gateway (e.g. 172.26.208.1/10.128.0.1)"
		iptv_gateway=$(read_check_ip)

		if [[ $iptv_has_alias -eq 1 ]]; then
			print "TV-LAN Alias (e.g. 10.0.0.1)"
			tvlan_ipaddr=$(read_check_ip)

			print "TV-LAN Netmask (e.g. 255.255.255.248)"
			tvlan_netmask=$(read_check_ip)
		else
			print "Enable video library? (y/n)"
			deco_enabled=$(read_check_yesno)

			print "Deco LAN IP addr? (e.g. 192.168.1.200)"
			deco_ipaddr=$(read_check_ip)
		fi
	fi
}

set_bird4() {
	echo -e "log syslog all;" > $1
	echo -e "" >> $1
	echo -e "router id 192.168.1.1;" >> $1
	echo -e "" >> $1
	echo -e "protocol kernel {" >> $1
	echo -e "\tpersist;" >> $1
	echo -e "\tscan time 20;" >> $1
	echo -e "\timport all;" >> $1
	echo -e "\texport all;" >> $1
	echo -e "}" >> $1
	echo -e "" >> $1
	echo -e "protocol device {" >> $1
	echo -e "\tscan time 10;" >> $1
	echo -e "}" >> $1
	echo -e "" >> $1
	echo -e "protocol static {" >> $1
	echo -e "\texport none;" >> $1
	echo -e "}" >> $1
	echo -e "" >> $1

	# VOIP RIPv2
	if [[ $voip_enabled -eq 1 ]]; then
		echo -e "filter voip_filter {" >> $1
		echo -e "\tif net ~ 10.0.0.0/8 then accept;" >> $1
		echo -e "\telse reject;" >> $1
		echo -e "}" >> $1
		echo -e "protocol rip voip {" >> $1
		echo -e "\timport all;" >> $1
		echo -e "\texport filter voip_filter;" >> $1
		echo -e "\tinterface \"eth0.3\";" >> $1
		echo -e "}" >> $1
		echo -e "" >> $1
	fi

	# IPTV RIPv2
	if [[ $iptv_enabled -eq 1 ]]; then
		echo -e "filter iptv_filter {" >> $1
		echo -e "\tif net ~ 172.26.0.0/16 then accept;" >> $1
		echo -e "\telse reject;" >> $1
		echo -e "}" >> $1
		echo -e "protocol rip iptv {" >> $1
		echo -e "\timport all;" >> $1
		echo -e "\texport filter iptv_filter;" >> $1
		echo -e "\tinterface \"eth0.2\";" >> $1
		echo -e "}" >> $1
		echo -e "" >> $1
	fi
}
set_igmpproxy() {
	echo -e "config igmpproxy" > $1
	echo -e "option quickleave 1" >> $1
	echo -e "" >> $1
	echo -e "config phyint" >> $1
	echo -e "option network eth0.2" >> $1
	echo -e "option direction upstream" >> $1
	echo -e "list altnet 172.26.0.0/16" >> $1
	echo -e "list altnet 192.168.1.0/24" >> $1
	echo -e "" >> $1
	echo -e "config phyint" >> $1
	echo -e "option network br-lan" >> $1
	echo -e "option direction downstream" >> $1
	echo -e "" >> $1
}
set_mcproxy() {
	echo -e "######################################" > $1
	echo -e "##-- mcproxy configuration script --##" >> $1
	echo -e "######################################" >> $1
	echo -e "" >> $1
	echo -e "# Protocol: IGMPv1|IGMPv2|IGMPv3 (IPv4) - MLDv1|MLDv2 (IPv6)" >> $1
	echo -e "protocol IGMPv2;" >> $1
	echo -e "" >> $1
	echo -e "# Proxy Instance: upstream ==> downstream" >> $1
	echo -e "pinstance iptv: \"eth0.2\" ==> \"br-lan\";" >> $1
	echo -e "" >> $1
}
set_firewall_user() {
	echo -e "# This file is interpreted as shell script." > $1
	echo -e "# Put your custom iptables rules here, they will" >> $1
	echo -e "# be executed with each firewall (re-)start." >> $1
	echo -e "" >> $1
	echo -e "# Internal uci firewall chains are flushed and recreated on reload, so" >> $1
	echo -e "# put custom rules into the root chains e.g. INPUT or FORWARD or into the" >> $1
	echo -e "# special user chains, e.g. input_wan_rule or postrouting_lan_rule." >> $1
	echo -e "" >> $1
}

igmpproxy_workaround_enable() {
	echo -e "# Put your custom commands here that should be executed once" > /etc/rc.local
	echo -e "# the system init finished. By default this file does nothing." >> /etc/rc.local
	echo -e "" >> /etc/rc.local
	echo -e "sleep 5 && /etc/init.d/igmpproxy start &" >> /etc/rc.local
	echo -e "" >> /etc/rc.local
	echo -e "exit 0" >> /etc/rc.local
	echo -e "" >> /etc/rc.local
}
igmpproxy_workaround_disable() {
	echo -e "# Put your custom commands here that should be executed once" > /etc/rc.local
	echo -e "# the system init finished. By default this file does nothing." >> /etc/rc.local
	echo -e "" >> /etc/rc.local
	echo -e "exit 0" >> /etc/rc.local
	echo -e "" >> /etc/rc.local
}

mode_network_cfg() {
	# Erase network config
	rm -rf /etc/config/network
	touch /etc/config/network
	print "Network config erased"

	# Loopback
	ucidef_set_interface_loopback &> /dev/null

	# Switch config
	ucidef_add_switch "switch0" "1" "1" &> /dev/null
	ucidef_add_switch_vlan "switch0" "1" "$switch_port_lan $switch_port_cpu$vlan_tagged_port" &> /dev/null
	if [[ $iptv_enabled -eq 1 ]]; then
		ucidef_add_switch_vlan "switch0" "2" "$switch_port_wan$vlan_tagged_port $switch_port_cpu$vlan_tagged_port" &> /dev/null
	fi
	if [[ $voip_enabled -eq 1 ]]; then
		ucidef_add_switch_vlan "switch0" "3" "$switch_port_wan$vlan_tagged_port $switch_port_cpu$vlan_tagged_port" &> /dev/null
	fi
	ucidef_add_switch_vlan "switch0" "6" "$switch_port_wan$vlan_tagged_port $switch_port_cpu$vlan_tagged_port" &> /dev/null

	# LAN
	uci set network.lan="interface" &> /dev/null
	uci set network.lan.ifname="eth0.1" &> /dev/null
	uci set network.lan.type="bridge" &> /dev/null
	uci set network.lan.proto="static" &> /dev/null
	uci set network.lan.ip6assign="60" &> /dev/null
	if [[ $iptv_enabled -eq 1 ]]; then
		uci set network.lan.igmp_snooping="1" &> /dev/null
		if [[ $iptv_has_alias -eq 1 ]]; then
			tvlan_cidr=$(netmask_cidr $tvlan_netmask)
			uci add_list network.lan.ipaddr="$tvlan_ipaddr/$tvlan_cidr" &> /dev/null
			uci add_list network.lan.ipaddr="192.168.1.1/24" &> /dev/null
		else
			uci set network.lan.ipaddr="192.168.1.1" &> /dev/null
			uci set network.lan.netmask="255.255.255.0" &> /dev/null
		fi
	else
		uci set network.lan.ipaddr="192.168.1.1" &> /dev/null
		uci set network.lan.netmask="255.255.255.0" &> /dev/null
	fi

	# IPTV
	if [[ $iptv_enabled -eq 1 ]]; then
		uci set network.iptv="interface" &> /dev/null
		uci set network.iptv.ifname="eth0.2" &> /dev/null
		uci set network.iptv.proto="static" &> /dev/null
		uci set network.iptv.ipaddr="$iptv_ipaddr" &> /dev/null
		uci set network.iptv.netmask="$iptv_netmask" &> /dev/null
		uci set network.iptv.gateway="$iptv_gateway" &> /dev/null
		uci set network.iptv.defaultroute="0" &> /dev/null
		uci set network.iptv.peerdns="0" &> /dev/null
	fi

	# VOIP
	if [[ $voip_enabled -eq 1 ]]; then
		uci set network.voip="interface" &> /dev/null
		uci set network.voip.ifname="eth0.3" &> /dev/null
		uci set network.voip.proto="dhcp" &> /dev/null
		uci set network.voip.defaultroute="0" &> /dev/null
		uci set network.voip.peerdns="0" &> /dev/null
	fi

	# WAN
	uci set network.wan="interface" &> /dev/null
	uci set network.wan.ifname="eth0.6" &> /dev/null
	uci set network.wan.proto="pppoe" &> /dev/null
	uci set network.wan.username="adslppp@telefonicanetpa" &> /dev/null
	uci set network.wan.password="adslppp" &> /dev/null

	# Load network config
	print "Network config loaded"

	# Save network config
	uci commit network
	print "Network config applied"
}
mode_firewall_cfg() {
	# Firewall default config
	rm -rf /etc/config/firewall
	cp /rom/etc/config/firewall /etc/config
	set_firewall_user "/etc/firewall.user"

	# IPTV Firewall
	if [[ $iptv_enabled -eq 1 ]]; then
		uci add firewall zone &> /dev/null
		uci set firewall.@zone[-1].name="iptv" &> /dev/null
		uci set firewall.@zone[-1].input="ACCEPT" &> /dev/null
		uci set firewall.@zone[-1].output="ACCEPT" &> /dev/null
		uci set firewall.@zone[-1].forward="REJECT" &> /dev/null
		uci set firewall.@zone[-1].network="iptv" &> /dev/null
		if [[ $iptv_has_alias -eq 0 ]]; then
			uci set firewall.@zone[-1].masq="1" &> /dev/null
		fi

		uci add firewall forwarding &> /dev/null
		uci set firewall.@forwarding[-1].src="lan" &> /dev/null
		uci set firewall.@forwarding[-1].dest="iptv" &> /dev/null

		uci add firewall forwarding &> /dev/null
		uci set firewall.@forwarding[-1].src="iptv" &> /dev/null
		uci set firewall.@forwarding[-1].dest="lan" &> /dev/null

		if [[ $iptv_has_alias -eq 0 ]]; then
			uci add firewall rule &> /dev/null
			uci set firewall.@rule[-1].target="ACCEPT" &> /dev/null
			uci set firewall.@rule[-1].src="wan" &> /dev/null
			uci set firewall.@rule[-1].dest="iptv" &> /dev/null
			uci set firewall.@rule[-1].enabled="1" &> /dev/null
			uci set firewall.@rule[-1].name="iptv_menu" &> /dev/null
			uci set firewall.@rule[-1].proto="all" &> /dev/null

			if [[ $deco_enabled -eq 1 ]]; then
				echo -e "iptables -t nat -A PREROUTING -p udp -d $iptv_ipaddr -j DNAT --to-destination $deco_ipaddr" >> "/etc/firewall.user"
				echo -e "" >> "/etc/firewall.user"
			fi
		fi
	fi

	# VOIP Firewall
	if [[ $voip_enabled -eq 1 ]]; then
		uci add firewall zone &> /dev/null
		uci set firewall.@zone[-1].name="voip" &> /dev/null
		uci set firewall.@zone[-1].input="ACCEPT" &> /dev/null
		uci set firewall.@zone[-1].output="ACCEPT" &> /dev/null
		uci set firewall.@zone[-1].forward="REJECT" &> /dev/null
		uci set firewall.@zone[-1].network="voip" &> /dev/null
		uci set firewall.@zone[-1].masq="1" &> /dev/null

		uci add firewall forwarding &> /dev/null
		uci set firewall.@forwarding[-1].src="lan" &> /dev/null
		uci set firewall.@forwarding[-1].dest="voip" &> /dev/null
	fi

	# Save firewall config
	uci commit firewall
	print "Firewall config saved"
}
mode_misc_cfg() {
	# bird4
	if [[ $voip_enabled -eq 1 || $iptv_enabled -eq 1 ]]; then
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
	if [[ $iptv_enabled -eq 1 ]]; then
		# Use mcproxy over igmpproxy
		if [ -f /usr/sbin/mcproxy ]; then
			# Set mcproxy config
			set_mcproxy "/etc/mcproxy.conf"
			print "mcproxy config applied"
			# Enable mcproxy
			service_enable "mcproxy"
		else
			# Set igmpproxy config
			set_igmpproxy "/etc/config/igmpproxy"
			print "igmpproxy config applied"
			# Enable igmpproxy
			service_disable "igmpproxy"
			igmpproxy_workaround_enable
			print "igmpproxy workaround enabled"
		fi
	else
		# Disable igmpproxy
		service_disable "igmpproxy"
		igmpproxy_workaround_disable
		print "igmpproxy workaround disabled"
	fi

	# DNS rebind protection
	if [[ $iptv_enabled -eq 1 ]]; then
		uci set dhcp.@dnsmasq[0].rebind_protection="0"
		uci commit dhcp
		print "DNS rebind protection disabled"
	else
		uci set dhcp.@dnsmasq[0].rebind_protection="1"
		uci commit dhcp
		print "DNS rebind protection enabled"
	fi
}

# Main fun
main() {
	# Print script info
	print "Movistar Imagenio Configuration Script $version"
	print "$DISTRIB_DESCRIPTION ($DISTRIB_TARGET)"
	print "Alvaro Fernandez Rojas (noltari@gmail.com)"

	space

	# Detect switch
	switch_detect
	print "Switch Info"
	print "\tSwitch Ports: $switch_port_num [$switch_port_list]"
	print "\tSwitch CPU Port: $switch_port_cpu"
	print "\tSwitch WAN Port: Unknown"
	print "\tSwitch LAN Ports: Unknown"

	space

	# Ask for wan port number
	wan_port_ask

	space

	# Print switch info
	print "Switch Info"
	print "\tSwitch Ports: $switch_port_num [$switch_port_list]"
	print "\tSwitch CPU Port: $switch_port_cpu"
	print "\tSwitch WAN Port: $switch_port_wan"
	print "\tSwitch LAN Ports: $switch_port_lan"

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
	print "Configuration successful!"
}

# Execute main
main

# Quit
exit 0

