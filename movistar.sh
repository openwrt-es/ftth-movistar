#!/bin/sh

# Includes
. /etc/openwrt_release
. /lib/functions/uci-defaults.sh

# Config
version="r13"
debug="/tmp/movistar.log"
vlan_tagged_port="t"

# Vars
switch_ifname_lan="eth0"
switch_ifname_wan="eth0"
switch_special_wan=0
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
dhcptv_enabled=0
network="192.168.1.0"

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
	while [[ ${#valid} -eq 0 ]]
	do
		read ip
		valid=$(ip_check "$ip")
	done

	# Return IP
	log $ip;
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
	log $answer;
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
			*) error "$dec is not recognised"; exit 1
		esac
	done
	echo "$nbits"
}

# Funs
switch_detect() {
	# Check if switch0 exists
	switch_exists=0
	( (swconfig dev $switch_name help) >> $debug 2>&1  ) && switch_exists=1
	if [[ $switch_exists -eq 0 ]]; then
		error "switch couldn't be detected"
		exit 1;
	fi

	# Detect special switch configurations
	switch_list=$(swconfig list)
	log $switch_list
	case $switch_list in
		*"ag71xx-mdio"* |\
		*"rtl8366"*)
			if [[ -d "/sys/class/net/eth1" ]]; then
				switch_special_wan=1
				switch_ifname_wan="eth1"
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
		if [[ ${#switch_port_list} -eq 0 ]]; then
			switch_port_list="$i"
		else
			switch_port_list="$switch_port_list $i"
		fi
	done
}
wan_port_ask() {
	if [[ $switch_special_wan -eq 1 ]]; then
		print "Your WAN interface has been detected as $switch_ifname_wan."
		print "Is this correct? (y/n)"
		switch_special_wan=$(read_check_yesno)

		if [[ $switch_special_wan -eq 0 ]]; then
			switch_ifname_wan="eth0"
		fi
	fi

	if [[ $switch_special_wan -eq 0 ]]; then
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
	fi
	log $switch_port_wan

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
network_ask() {
	print "You want to customize your network (${network} is default net)?(y/n)"
	network_custom=$(read_check_yesno)
	# Only need the network part, then when take only take the firts 3 octects
	if [[ $network_custom -eq 1 ]]; then
		network=$(echo $(read_check_ip)|cut -d"." -f-3)
	else
		network=$(echo ${network}|cut -d"." -f-3)
	fi
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
			print "Enable VOD (Video On Demand)? (y/n)"
			print "Bug: may cause problems with NAT-PMP"
			deco_enabled=$(read_check_yesno)

			if [[ $deco_enabled -eq 1 ]]; then
				print "VOD IPTV decoder LAN IP addr? (e.g. 192.168.1.200)"
				print "Bug: only 1 VOD IPTV decoder is supported right now."
				deco_ipaddr=$(read_check_ip)
			fi

			print "Enable DHCP for IPTV decoders? (y/n)"
			dhcptv_enabled=$(read_check_yesno)
		fi
	fi
}

set_bird4() {
	echo -e "log syslog all;" > $1
	echo -e "" >> $1
	echo -e "router id ${network}.1;" >> $1
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
	if [[ $iptv_enabled -eq 1 && $iptv_has_alias -eq 0 ]]; then
		echo -e "\texport all;" >> $1
		echo -e "\troute 172.26.0.0/16 via $iptv_gateway;" >> $1
	else
		echo -e "\texport none;" >> $1
	fi
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
		echo -e "\tinterface \"$switch_ifname_wan.3\";" >> $1
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
		echo -e "\tinterface \"$switch_ifname_wan.2\";" >> $1
		echo -e "}" >> $1
		echo -e "" >> $1
	fi
}
set_igmpproxy() {
	echo -e "config igmpproxy" > $1
	echo -e "option quickleave 1" >> $1
	echo -e "" >> $1
	echo -e "config phyint" >> $1
	echo -e "option network $switch_ifname_wan.2" >> $1
	echo -e "option direction upstream" >> $1
	echo -e "list altnet 172.26.0.0/16" >> $1
	echo -e "list altnet ${network}.0/24" >> $1
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
	echo -e "pinstance iptv: \"$switch_ifname_wan.2\" ==> \"br-lan\";" >> $1
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
	ucidef_set_interface_loopback >> $debug 2>&1 

	# Switch config
	ucidef_add_switch "switch0" "1" "1" >> $debug 2>&1 
	ucidef_add_switch_vlan "switch0" "1" "$switch_port_lan $switch_port_cpu$vlan_tagged_port" >> $debug 2>&1 
	if [[ $switch_special_wan -eq 0 ]]; then
		if [[ $iptv_enabled -eq 1 ]]; then
			ucidef_add_switch_vlan "switch0" "2" "$switch_port_wan$vlan_tagged_port $switch_port_cpu$vlan_tagged_port" >> $debug 2>&1 
		fi
		if [[ $voip_enabled -eq 1 ]]; then
			ucidef_add_switch_vlan "switch0" "3" "$switch_port_wan$vlan_tagged_port $switch_port_cpu$vlan_tagged_port" >> $debug 2>&1 
		fi
		ucidef_add_switch_vlan "switch0" "6" "$switch_port_wan$vlan_tagged_port $switch_port_cpu$vlan_tagged_port" >> $debug 2>&1 
	fi

	# LAN
	uci set network.lan="interface" >> $debug 2>&1 
	uci set network.lan.ifname="$switch_ifname_lan.1" >> $debug 2>&1 
	uci set network.lan.type="bridge" >> $debug 2>&1 
	uci set network.lan.proto="static" >> $debug 2>&1 
	uci set network.lan.ip6assign="60" >> $debug 2>&1 
	if [[ $iptv_enabled -eq 1 ]]; then
		uci set network.lan.igmp_snooping="1" >> $debug 2>&1 
		if [[ $iptv_has_alias -eq 1 ]]; then
			tvlan_cidr=$(netmask_cidr $tvlan_netmask)
			uci add_list network.lan.ipaddr="$tvlan_ipaddr/$tvlan_cidr" >> $debug 2>&1 
			uci add_list network.lan.ipaddr="${network}.1/24" >> $debug 2>&1 
		else
			uci set network.lan.ipaddr="${network}.1" >> $debug 2>&1 
			uci set network.lan.netmask="255.255.255.0" >> $debug 2>&1 
		fi
	else
		uci set network.lan.ipaddr="${network}.1" >> $debug 2>&1 
		uci set network.lan.netmask="255.255.255.0" >> $debug 2>&1 
	fi

	# IPTV
	if [[ $iptv_enabled -eq 1 ]]; then
		uci set network.iptv="interface" >> $debug 2>&1 
		uci set network.iptv.ifname="$switch_ifname_wan.2" >> $debug 2>&1 
		uci set network.iptv.proto="static" >> $debug 2>&1 
		uci set network.iptv.ipaddr="$iptv_ipaddr" >> $debug 2>&1 
		uci set network.iptv.netmask="$iptv_netmask" >> $debug 2>&1 
		uci set network.iptv.gateway="$iptv_gateway" >> $debug 2>&1 
		uci set network.iptv.defaultroute="0" >> $debug 2>&1 
		uci set network.iptv.peerdns="0" >> $debug 2>&1 
	fi

	# VOIP
	if [[ $voip_enabled -eq 1 ]]; then
		uci set network.voip="interface" >> $debug 2>&1 
		uci set network.voip.ifname="$switch_ifname_wan.3" >> $debug 2>&1 
		uci set network.voip.proto="dhcp" >> $debug 2>&1 
		uci set network.voip.defaultroute="0" >> $debug 2>&1 
		uci set network.voip.peerdns="0" >> $debug 2>&1 
	fi

	# WAN
	uci set network.wan="interface" >> $debug 2>&1 
	uci set network.wan.ifname="$switch_ifname_wan.6" >> $debug 2>&1 
	uci set network.wan.proto="pppoe" >> $debug 2>&1 
	uci set network.wan.username="adslppp@telefonicanetpa" >> $debug 2>&1 
	uci set network.wan.password="adslppp" >> $debug 2>&1 

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
		uci add firewall zone >> $debug 2>&1 
		uci set firewall.@zone[-1].name="iptv" >> $debug 2>&1 
		uci set firewall.@zone[-1].input="ACCEPT" >> $debug 2>&1 
		uci set firewall.@zone[-1].output="ACCEPT" >> $debug 2>&1 
		uci set firewall.@zone[-1].forward="REJECT" >> $debug 2>&1 
		uci set firewall.@zone[-1].network="iptv" >> $debug 2>&1 
		if [[ $iptv_has_alias -eq 0 ]]; then
			uci set firewall.@zone[-1].masq="1" >> $debug 2>&1 
		fi

		uci add firewall forwarding >> $debug 2>&1 
		uci set firewall.@forwarding[-1].src="lan" >> $debug 2>&1 
		uci set firewall.@forwarding[-1].dest="iptv" >> $debug 2>&1 

		uci add firewall forwarding >> $debug 2>&1 
		uci set firewall.@forwarding[-1].src="iptv" >> $debug 2>&1 
		uci set firewall.@forwarding[-1].dest="lan" >> $debug 2>&1 

		if [[ $iptv_has_alias -eq 0 && $deco_enabled -eq 1 ]]; then
			echo -e "iptables -t nat -A PREROUTING -s 172.26.0.0/16 -p udp -d $iptv_ipaddr -j DNAT --to-destination $deco_ipaddr" >> "/etc/firewall.user"
			echo -e "" >> "/etc/firewall.user"
		fi
	fi

	# VOIP Firewall
	if [[ $voip_enabled -eq 1 ]]; then
		uci add firewall zone >> $debug 2>&1 
		uci set firewall.@zone[-1].name="voip" >> $debug 2>&1 
		uci set firewall.@zone[-1].input="ACCEPT" >> $debug 2>&1 
		uci set firewall.@zone[-1].output="ACCEPT" >> $debug 2>&1 
		uci set firewall.@zone[-1].forward="REJECT" >> $debug 2>&1 
		uci set firewall.@zone[-1].network="voip" >> $debug 2>&1 
		uci set firewall.@zone[-1].masq="1" >> $debug 2>&1 

		uci add firewall forwarding >> $debug 2>&1 
		uci set firewall.@forwarding[-1].src="lan" >> $debug 2>&1 
		uci set firewall.@forwarding[-1].dest="voip" >> $debug 2>&1 
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
		uci set dhcp.@dnsmasq[0].rebind_protection="0" >> $debug 2>&1 
		uci commit dhcp
		print "DNS rebind protection disabled"
	else
		uci set dhcp.@dnsmasq[0].rebind_protection="1" >> $debug 2>&1 
		uci commit dhcp
		print "DNS rebind protection enabled"
	fi

	# DHCP
	if [[ $dhcptv_enabled -eq 1 ]]; then
		uci set dhcp.lan.networkid="tag:!dhcptv" >> $debug 2>&1 
		uci set dhcp.lan.start="100" >> $debug 2>&1 
		uci set dhcp.lan.limit="100" >> $debug 2>&1 

		uci set dhcp.vendortv=vendorclass >> $debug 2>&1 
		uci set dhcp.vendortv.vendorclass="IAL" >> $debug 2>&1 
		uci set dhcp.vendortv.networkid="dhcptv" >> $debug 2>&1 

		uci set dhcp.dhcptv=dhcp >> $debug 2>&1 
		uci set dhcp.dhcptv.networkid="tag:dhcptv" >> $debug 2>&1 
		uci set dhcp.dhcptv.interface="lan" >> $debug 2>&1 
		uci set dhcp.dhcptv.start="200" >> $debug 2>&1 
		uci set dhcp.dhcptv.limit="23" >> $debug 2>&1 
		uci set dhcp.dhcptv.leasetime="24h" >> $debug 2>&1 
		uci delete dhcp.dhcptv.dhcp_option >> $debug 2>&1 
		uci add_list dhcp.dhcptv.dhcp_option="6,172.26.23.3" >> $debug 2>&1 
		uci add_list dhcp.dhcptv.dhcp_option="240,:::::239.0.2.10:22222:v6.0:239.0.2.30:22222" >> $debug 2>&1 

		uci commit dhcp
		print "IPTV DHCP server configured"
	fi
}

# Main fun
main() {
	# Print CPU info
	cat /proc/cpuinfo &> $debug

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
	if [[ $switch_special_wan -eq 0 ]]; then
		print "\tSwitch WAN Port: Unknown"
	else
		print "\tSwitch WAN Interface: $switch_ifname_wan"
	fi
	print "\tSwitch LAN Ports: Unknown"

	space

	# Ask for wan port number
	wan_port_ask

	space

	# Print switch info
	print "Switch Info"
	print "\tSwitch Ports: $switch_port_num [$switch_port_list]"
	print "\tSwitch CPU Port: $switch_port_cpu"
	if [[ $switch_special_wan -eq 0 ]]; then
		print "\tSwitch WAN Port: $switch_port_wan"
	else
		print "\tSwitch WAN Interface: $switch_ifname_wan"
	fi
	print "\tSwitch LAN Ports: $switch_port_lan"

	space

	# Ask for network
	network_ask

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
