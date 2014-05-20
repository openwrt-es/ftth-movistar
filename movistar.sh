#!/bin/sh

# Includes
. /etc/openwrt_release
. /lib/functions/uci-defaults.sh

# Config
version=r2
debug=0
vlan_tagged_port="t"

# Vars
switch_ifname="eth0"
switch_name="switch0"
switch_port_min=0
switch_port_max=0
switch_port_list=-1
switch_port_num=0
switch_port_cpu=-1
switch_port_wan=-1
switch_port_lan=-1
config_mode=0
iptv_ipaddr=""
iptv_netmask=""
iptv_gateway=""
iptv_has_alias=-1
tvlan_ipaddr=""
tvlan_netmask=""

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
	local is_valid
	is_valid=$(echo $1 | awk -F"\." ' $0 ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ && $1 <=255 && $2 <= 255 && $3 <= 255 && $4 <= 255 ')
	echo $is_valid
}
read_check_ip() {
	local ip=""
	local valid=""

	while [[ ${#valid} -eq 0 ]]
	do
		read ip
		valid=$(ip_check "$ip")
	done

	echo $ip
}

# Funs
switch_detect() {
	# Check if switch0 exists
	switch_exists=0
	( (swconfig list | grep $switch_name) &> /dev/null ) && switch_exists=1
	if [[ $switch_exists -eq 0 ]]; then
		error "switch couldn't be detected"
		exit 1;
	fi

	# Detect switch ports
	switch_help=$(swconfig dev $switch_name help)
	switch_port_cpu=$(echo $switch_help | sed "s/cpu @ /&\n/;s/.*\n//;s/), vlans/\n&/;s/\n.*//")
	switch_port_num=$(echo $switch_help | sed "s/, ports: /&\n/;s/.*\n//;s/ (cpu @ /\n&/;s/\n.*//")

	switch_port_max=$(($switch_port_num - 1))
	switch_port_list=""
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
	error=0
	if [[ $switch_port_wan -lt $switch_port_min ]]; then
		error=1
	fi
	if [[ $switch_port_wan -gt $switch_port_max ]]; then
		error=1
	fi
	if [[ $switch_port_wan -eq $switch_port_cpu ]]; then
		error=1
	fi
	if [[ $error -eq 1 ]]; then	
		wan_port_ask
	fi

	# Calculate lan ports
	switch_port_lan=""
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
mode_ask() {
	# Print mode info
	print "Services"
	print "\t1: WAN"
	print "\t2: WAN + VOIP"
	print "\t3: WAN + VOIP + IPTV"

	# Read input
	read config_mode

	# Check selected option
	error=1
	if [[ $config_mode -eq 1 ]]; then
		debug "Selected: WAN"
		error=0
	fi
	if [[ $config_mode -eq 2 ]]; then
		debug "Selected: WAN + VOIP"
		error=0
	fi
	if [[ $config_mode -eq 3 ]]; then
		debug "Selected: WAN + VOIP + IPTV"
		error=0
	fi
	if [[ $error -eq 1 ]]; then
		mode_ask
	fi
}
iptv_ask() {
	print "IPTV IP Address"
	iptv_ipaddr=$(read_check_ip)

	print "IPTV Netmask"
	iptv_netmask=$(read_check_ip)

	print "IPTV Gateway"
	iptv_gateway=$(read_check_ip)

	case $iptv_ipaddr in
			"10."*)
					iptv_has_alias=0
					;;
			"172."*)
					iptv_has_alias=1
					;;
	esac

	if [[ $iptv_has_alias -eq 1 ]]; then
		print "TV-LAN Alias"
		tvlan_ipaddr=$(read_check_ip)

		print "TV-LAN Netmask"
		tvlan_netmask=$(read_check_ip)
	fi
}

network_empty() {
	rm -rf /etc/config/network
	touch /etc/config/network
}
firewall_default() {
	rm -rf /etc/config/firewall
	cp /rom/etc/config/firewall /etc/config
}
set_interface_wan() {
	local ifname=$1

	uci batch <<EOF
set network.wan='interface'
set network.wan.ifname='$ifname'
set network.wan.proto='pppoe'
set network.wan.username='adslppp@telefonicanetpa'
set network.wan.password='adslppp'
EOF
}
set_interface_voip() {
	local ifname=$1

	uci batch <<EOF
set network.voip='interface'
set network.voip.ifname='$ifname'
set network.voip.proto='dhcp'
set network.voip.defaultroute='0'
set network.voip.peerdns='0'
EOF

	ucidef_add_switch_vlan "switch0" "3" "$switch_port_wan$vlan_tagged_port $switch_port_cpu$vlan_tagged_port"
}
set_interface_iptv() {
	local ifname=$1
	local ipaddr=$2
	local netmask=$3
	local gateway=$4

	uci batch <<EOF
set network.iptv='interface'
set network.iptv.ifname='$ifname'
set network.iptv.proto='static'
set network.iptv.ipaddr='$ipaddr'
set network.iptv.netmask='$netmask'
set network.iptv.gateway='$gateway'
set network.iptv.defaultroute='0'
set network.iptv.peerdns='0'
EOF

	ucidef_add_switch_vlan "switch0" "2" "$switch_port_wan$vlan_tagged_port $switch_port_cpu$vlan_tagged_port"
}
set_interface_tvlan() {
	local interface=$1
	local ipaddr=$2
	local netmask=$3

	uci add network alias
	uci set network.@alias[-1].interface="$interface"
	uci set network.@alias[-1].proto='static'
	uci set network.@alias[-1].ipaddr="$ipaddr"
	uci set network.@alias[-1].netmask="$netmask"
}
enable_igmp_snooping() {
	uci set network.lan.igmp_snooping=1
}
network_common() {
	ucidef_set_interface_loopback
	ucidef_set_interface_lan "eth0.1"
	set_interface_wan "eth0.6"
	ucidef_add_switch "switch0" "1" "1"
	ucidef_add_switch_vlan "switch0" "1" "$switch_port_lan $switch_port_cpu$vlan_tagged_port"
	ucidef_add_switch_vlan "switch0" "6" "$switch_port_wan$vlan_tagged_port $switch_port_cpu$vlan_tagged_port"
}
set_firewall_voip() {
	uci add firewall zone
	uci set firewall.@zone[-1].name=voip
	uci set firewall.@zone[-1].input=ACCEPT
	uci set firewall.@zone[-1].output=ACCEPT
	uci set firewall.@zone[-1].forward=REJECT
	uci set firewall.@zone[-1].network=voip
	uci set firewall.@zone[-1].masq=1

	uci add firewall forwarding
	uci set firewall.@forwarding[-1].src=lan
	uci set firewall.@forwarding[-1].dest=voip
}
set_firewall_iptv() {
	uci add firewall zone
	uci set firewall.@zone[-1].name=iptv
	uci set firewall.@zone[-1].input=ACCEPT
	uci set firewall.@zone[-1].output=ACCEPT
	uci set firewall.@zone[-1].forward=REJECT
	uci set firewall.@zone[-1].network=iptv

	uci add firewall forwarding
	uci set firewall.@forwarding[-1].src=lan
	uci set firewall.@forwarding[-1].dest=iptv
	uci add firewall forwarding
	uci set firewall.@forwarding[-1].src=iptv
	uci set firewall.@forwarding[-1].dest=lan
}
service_disable() {
	# Check if service is installed
	if [ -f /etc/init.d/$1 ]; then
		/etc/init.d/$1 stop
		/etc/init.d/$1 disable
		print "\t$1 disabled"
	fi
}
service_enable() {
	# Check if service is installed
	if [ -f /etc/init.d/$1 ]; then
		/etc/init.d/$1 enable
		/etc/init.d/$1 stop
		/etc/init.d/$1 start
		print "\t$1 enabled"
	fi
}
set_bird4_voip() {
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
	echo -e "filter voip_filter {" >> $1
	echo -e "\tif net ~ 10.0.0.0/8 then accept;" >> $1
	echo -e "\telse reject;" >> $1
	echo -e "}" >> $1
	echo -e "protocol rip {" >> $1
	echo -e "\timport all;" >> $1
	echo -e "\texport filter voip_filter;" >> $1
	echo -e "\tinterface \"eth0.3\";" >> $1
	echo -e "}" >> $1
	echo -e "" >> $1
}
set_bird4_voip_iptv() {
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
	echo -e "filter iptv_filter {" >> $1

	case $iptv_ipaddr in
			"10."*)
					echo -e "\tif net ~ 10.0.0.0/8 then accept;" >> $1
					;;
			"172."*)
					echo -e "\tif net ~ 172.26.0.0/16 then accept;" >> $1
					;;
	esac

	echo -e "\telse reject;" >> $1
	echo -e "}" >> $1
	echo -e "protocol rip iptv {" >> $1
	echo -e "\timport all;" >> $1
	echo -e "\texport filter iptv_filter;" >> $1
	echo -e "\tinterface \"eth0.2\";" >> $1
	echo -e "}" >> $1
	echo -e "" >> $1
}
set_igmpproxy_iptv() {
	echo -e "config igmpproxy" > $1
	echo -e "option quickleave 1" >> $1
	echo -e "" >> $1
	echo -e "config phyint" >> $1
	echo -e "option network iptv" >> $1
	echo -e "option direction upstream" >> $1

	case $iptv_ipaddr in
			"10."*)
					echo -e "list altnet 172.0.0.0/8" >> $1
					;;
			"172."*)
					echo -e "list altnet 172.26.0.0/16" >> $1
					;;
	esac

	echo -e "" >> $1
	echo -e "config phyint" >> $1
	echo -e "option network lan" >> $1
	echo -e "option direction downstream" >> $1
	echo -e "" >> $1
}

mode_run() {
	# Check configuration mode
	if [[ $config_mode -eq 1 ]]; then
		print "WAN"

		# Erase network config
		network_empty
		print "\tNetwork config erased"
		# Load network config
		network_common &> /dev/null
		print "\tNetwork config loaded"
		# Save network config
		uci commit network
		print "\tNetwork config applied"

		# Firewall default config
		firewall_default
		print "\tFirewall config applied"
		# Load firewall config
		print "\tFirewall config loaded"
		# Save firewall config
		uci commit firewall
		print "\tFirewall config saved"

		# Disable bird4
		service_disable "bird4"

		# Disable igmpproxy
		service_disable "igmpproxy"
	fi
	if [[ $config_mode -eq 2 ]]; then
		print "WAN + VOIP"

		# Erase network config
		network_empty
		print "\tNetwork config erased"
		# Load network config
		network_common &> /dev/null
		set_interface_voip "eth0.3" &> /dev/null
		print "\tNetwork config loaded"
		# Save network config
		uci commit network
		print "\tNetwork config saved"

		# Erase firewall config
		firewall_default
		print "\tFirewall config erased"
		# Load firewall config
		set_firewall_voip &> /dev/null
		print "\tFirewall config loaded"
		# Save firewall config
		uci commit firewall
		print "\tFirewall config saved"

		# Set bird4 config
		set_bird4_voip "/etc/bird4.conf"
		set_bird4_voip "/etc/bird.conf"
		print "\tbird4 config applied"
		# Enable bird4
		service_enable "bird4"

		# Disable igmpproxy
		service_disable "igmpproxy"
	fi
	if [[ $config_mode -eq 3 ]]; then
		print "WAN + VOIP + IPTV"

		# Erase network config
		network_empty
		print "\tNetwork config erased"
		# Load network config
		network_common &> /dev/null
		set_interface_voip "eth0.3" &> /dev/null
		iptv_ask
		set_interface_iptv "eth0.2" "$iptv_ipaddr" "$iptv_netmask" "$iptv_gateway" &> /dev/null
		if [[ $iptv_has_alias -eq 1 ]]; then
			set_interface_tvlan "lan" "$tvlan_ipaddr" "$tvlan_netmask" &> /dev/null
		fi
		enable_igmp_snooping
		print "\tNetwork config loaded"
		# Save network config
		uci commit network
		print "\tNetwork config saved"

		# Erase firewall config
		firewall_default
		print "\tFirewall config erased"
		# Load firewall config
		set_firewall_voip &> /dev/null
		set_firewall_iptv &> /dev/null
		print "\tFirewall config loaded"
		# Save firewall config
		uci commit firewall
		print "\tFirewall config saved"

		# Set bird4 config
		set_bird4_voip_iptv "/etc/bird4.conf"
		set_bird4_voip_iptv "/etc/bird.conf"
		print "\tbird4 config applied"
		# Enable bird4
		service_enable "bird4"

		# Set igmpproxy config
		set_igmpproxy_iptv "/etc/config/igmpproxy"
		print "\tigmpproxy config applied"
		# Enable igmpproxy
		service_enable "igmpproxy"
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

	# Execute configuration mode
	mode_run

	space

	# End
	print "Configuration successful!"
}

# Execute main
main

# Quit
exit 0

