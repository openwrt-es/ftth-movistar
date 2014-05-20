#!/bin/sh

# Includes
. /etc/openwrt_release
. /lib/functions/uci-defaults.sh

# Config
version=r1
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
set_bird4_disable() {
	# Check if bird is installed
	if [ -f /etc/init.d/bird4 ]; then
		/etc/init.d/bird4 stop
		/etc/init.d/bird4 disable
		print "\tbird4 disabled"
	fi
}
set_bird4_enable() {
	# Check if bird is installed
	if [ -f /etc/init.d/bird4 ]; then
		/etc/init.d/bird4 enable
		/etc/init.d/bird4 stop
		/etc/init.d/bird4 start
		print "\tbird4 enabled"
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
		set_bird4_disable
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
		set_bird4_enable
	fi
	if [[ $config_mode -eq 3 ]]; then
		print "WAN + VOIP + IPTV"

		print "\tNot implemented!"
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

