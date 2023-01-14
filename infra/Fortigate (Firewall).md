#=====================================================================

CLI Console # top right click on sign ">_"

#=====================================================================

ctrl+C #stop running command

#=====================================================================

#see if there is a disk attached to, fortiOS 6.4.4 without HHD

Log Settings-CLI Console- get sys stat - Log Hard Disk

#=====================================================================

#download FortiGate configuration file & Debug log from GUI

Admin -> Configuration -> Backup select 'Local PC' in 'Backup to' and select'OK'

System -> Settings -> Debug Logs and select the 'Download' button

#=====================================================================

#Selecting an alternate firmware for the next reboot

FGT # diag sys flash list #lists the FortiOS image files installed in both partitions

FGT# execute set-next-reboot {primary | secondary # revert to the previous or other firmware

FGT # execute reboot

#=====================================================================

execute ping 8.8.8.8

execute ping-options view

execute ping-options source 192.168.1.4

execute traceroute 8.8.8.8

execute telnet targethost

#=====================================================================

diagnose sys session list #Show Session Table

#=====================================================================

dia deb res

diag debug console timestamp enable

diag debug flow show console enable

diag debug flow show function-name enable

diag debug flow filter saddr x.x.x.x --> x.x.x.x is the source IP

diag debug flow filter daddr x.x.x.x --> x.x.x.x is the destination IP

dia deb flow trace start 100

diag debug enable

#=====================================================================

#list of interfaces

get sys int phy

get sys int

config system interface #Show network interface configuration:

diagnose hardware deviceinfo nic #Show all nics

diagnose hardware deviceinfo nic dmz #Show all info for specific nic

#=====================================================================

get router info ospf status #Get Router Status

get router info ospf neighbor all #Neighbor status (neighbours have state up/down)

excecute router clear ospf process #Delete all OSPF entries

diagnose sniffer packet any ‘proto 89’ 4 #Trace / Sniff for OSPF packets

#Enable debug output

diagnose ip router ospf all enable

diagnose ipo router ospf level info

#Debug OSPF

dignose ip router ospf all enable

diagnose ip router ospf level info

diagnose debug enable

#=====================================================================

Debug traffic flow through the fortigate

diagnose debug enable

diagnose debug flow show console enable

diagnose debug flow filter add 10.10.0.1

diagnose debug flow trace start 100

#=====================================================================

#Set certificate for admin interface

config system global

set admin-server-cert certname

end

#=====================================================================

get ipsec tunnel list #Show ipsec tunnels

Troubleshoot VPN connections

diag debug application ike -1

diagnose vpn ike log-filter clear

diagnose vpn ike log-filter dst-addr 1.2.3.4

diagnose debug app ike 255

diagnose debug enable

#=====================================================================

get router info routing-table all #verify the routing table

show system interface port1 #Verify that all appropriate services are opened on the interface that is being accessed. (telnet, http...)

config firewall policy # If the interface is accessed via another port of the FortiGate, a firewall policy must exist to allow this traffic

- Is traffic arriving to the FortiGate and does it arrive on the expected port?

- Is the ARP resolution correct for the targeted next-hop?

- Is the traffic exiting the FortiGate to the destination?

- Is the traffic sent back to the source?

#stop the sniffer, type CTRL+C.

diagnose sniffer packet any "(host <PC1> and host <PC2>) and icmp" 4

diagnose sniffer packet any "host <PC1> and host <PC2>" 4

Debug flow

# diag debug enable

# diag debug flow filter           <----- Find the options to filter below.

# diag debug console timestamp enable

# diag debug flow show iprope enable

# diag debug flow trace start 100 <----- This will display 100 packets for this flow.

# diag debug enabl

diag debug flow trace stop #stop all other debug

Filter based on Protocol

# diagnose debug flow filter proto 1 #(proto = protocol number)

protocol number 1 = ICMP (ping)

protocol number 6 = TCP

protocol number 17 = UDP

Filter only ping that relates to the IP address

# diagnose debug flow filter addr x.x.x.x

# diagnose debug flow filter proto

firewall statistic show

sys session full-stat #session table

#=====================================================================

Change vdom:

config vdom

edit vdomname

#=====================================================================

# Convert Fortigate Traffic Capture to Wireshark Capture

Fgt2eth.exe –in <LOG_FILE_NAME> -out <FILENAME.pcap>

#=====================================================================

# diagnose sniffer packet <interface> '<filter>' <level> <count> <tsformat>

# diagnose sniffer packet any

# diagnose sniffer packet any '' 4

# diagnose sniffer packet any ‘none’ 4 10 a'

# diagnose sniffer packet any 'icmp' 1

# diagnose sniffer packet any ‘ udp and port 53 ‘ 4 3 a

# diagnose sniffer packet any ‘src host 8.8.8.8 and dst host 10.10.4.41 ‘ 4 3 a

# diagnose sniffer packet any 'src host 192.168.10.1 and dst host 192.168.10.254' 4

# diagnose sniffer packet any ‘src host 10.10.4.41 and tcp and port 443 ‘ 4 3 a

# diagnose sniffer packet any 'host 192.168.10.1 and tcp port 80' 6

# diagnose sniffer packet any ‘host 10.10.4.41 and icmp ‘ 4 6 a

Match TTL = 1

# diagnose sniffer packet port2 "ip[8:1] = 0x01"

Match Source IP address = 192.168.1.2

# diagnose sniffer packet internal "(ether[26:4]=0xc0a80102)"

Match Source MAC = 00:09:0f:89:10:ea

# diagnose sniffer packet internal "(ether[6:4]=0x00090f89) and (ether[10:2]=0x10ea)"

Match Destination MAC = 00:09:0f:89:10:ea

# diagnose sniffer packet internal "(ether[0:4]=0x00090f89) and (ether[4:2]=0x10ea)"

Match ARP packets only

# diagnose sniffer packet internal "ether proto 0x0806"

Match packets with RST flag set:

# diagnose sniffer packet internal "tcp[13] & 4 != 0"

Match packets with SYN flag set:

# diagnose sniffer packet internal "tcp[13] & 2 != 0"

Match packets with SYN-ACK flag set:

# diagnose sniffer packet internal "tcp[13] = 18"

#Normally the verbose 4 is being used but this is not convertable to PCAP

diagnose sniffer packet any 'host 172.16.33.67 and host 186.76.159.194' 4 0

#the output can be CONVERTED to a PCAP

diagnose sniffer packet any 'host 172.16.33.67 and host 186.76.159.194' 6 0

diagnose sniffer packet any "host 10.200.1.10 and host 10.200.2.10" 4

diagnose sniffer packet any "host 10.200.2.11 and icmp" 4

diag sniff packet any ‘host 8.8.8.8 and icmp’ 6 0

#=====================================================================

# diag sys ha checksum cluster #verify the HA checksum to make sure the HA is in sync

#config system ha # switch to HA mode

(ha) #sh full # show full configuration

(ha) # end

exec ha manage 0 admin # switch to other node in HA mode

#=====================================================================

get system status # firmware version

get system performance status

get system performance top #(use Shift+M for memory usage

#=====================================================================

execute log filter dump

execute log filter category 0

execute log filter field hostname www.google.ch

execute log display

#=====================================================================

diag debug enable

diag debug authd fsso list

diag debug authd fsso server-status

diag debug authd fsso summary

diag debug authd fsso clear-logons

diag debug authd fsso refresh-logons

diag debug authd fsso refresh-groups

#=====================================================================

diagnose test application ssl 0

diagnose test application ssl 4 #SSL Proxy Usage

diagnose test application ssl 44 #

#===============================================Show info per connection======================

#Troubleshooting Fortigate LDAP

# <LDAP server_name> is the name of LDAP object on FortiGate (not actual LDAP server name)

#LDAP support 3 types of authentication (Binding): anonymous, simple and SASL authentication.

#FGT# diagnose test authserver ldap LDAP_SERVER user1 password

diagnose debug {enable|disable}

FGT# diagnose debug enable

FGT# diagnose debug application fnbamd 255

#===============================================Show info per connection======================

FortiOS v7.2.x

Log & Report-System Events- VPN Events

#=====================================================================

FortiAnalyzer

All Reports-Fortigate Reports-VPN Report

#=====================================================================

#Troubleshoot webfilter CLI FortiOS 7.2x

Test #1: Is the service enabled? Make sure that at least one firewall policy has a Web Filter and SSL/SSH Inspection profile enabled

If the output shows that the service is not enabled, create a firewall policy and enable Web Filtering inspection there.

# diagnose debug rating

Test #2: Can the FortiGate get to the Internet DNS by IP?

Some ISPs and networks block ICMP (ping) traffic. This should be taken into account before considering the test to have failed.

# execute ping 8.8.8.8

Test #3: Can the FortiGate resolve FQDNs?

Some ISPs and networks block ICMP (ping) traffic. 

This should be taken into account before considering the test to have failed. 

The important part of this test is that the unit successfully resolves an FQDN to an IP, not that the ping suceeds.

# exec ping google.com

Test #4: Can the FortiGate resolve a specific host name?

Above mentioned FQDNs might not be pingable, it is an expected behavior.Key point here is to see, if these FQDNs are resolved

# exec ping service.fortiguard.net

# exec ping update.fortiguard.net

# exec ping guard.fortinet.net

change the Fortiguard Web Filtering Port in CLI the following way:

change the Fortiguard Web Filtering Port in CLI the following way

# config system fortiguard

(fortiguard) set port 53

(fortiguard) end

In case changing the Web Filtering port cannot solve the problem with Web Filtering, try to change the source port range for self-originated traffic

# config system global

(global) set ip-src-port-range 1031-4999

(global) end

# diagnose test application urlfilter 99

Starting from FortiOS 6.4, by default it use HTTPS on ports 443

In order to change the port/protocol please follow the below CLI configuration.

By disabling anycast settings it will be possible to view the options to select the protocol and port.

# config system fortiguard

set fortiguard-anycast disable

Anycast servers - starting with FortiOS 6.4 the default setting to reach FortiGuard is anycast

disable anycast and switch back to unicast servers.

config system fortiguard

set fortiguard-anycast disable

set protocol udp

set port 8888

set sdns-server-ip 208.91.112.220 <-- IMPORTANT TO ADD THIS OR ANY OTHER FDN SERVER TO PREVENT DOWNTIME!

end

# show system fortiguard

config system fortiguard

end

# get system fortiguard

fortiguard-anycast : enable

fortiguard-anycast-source: fortinet

protocol : https

port : 443

load-balance-servers: 1

auto-join-forticloud: enable

update-server-location: automatic

sandbox-region :

update-ffdb : enable

update-uwdb : enable

update-extdb : enable

update-build-proxy : enable

vdom :

auto-firmware-upgrade: disable

#

Navigate to Log & Report > Security Events > Web Filter click on download on the left

#=====================================================================

#access secondary unit of HA cluster via CLI

# execute ha manage [ID] [username] #the primary unit CLI

# execute ha manage 1 EXAMPLE < ----- 1 is the ID of secondary unit and EXAMPLE is the admin username.

#=====================================================================

#Troubleshooting EmailFilter

# diagnose emailfilter fortishield servers

Locale : english

Service : Web-filter

Status : Enable

License : Contract

Service : Antispam

Status : Disable

Service : Virus Outbreak Prevention

Status : Disable

Num. of servers : 3

Protocol : https

Port : 443

Anycast : Enable

Default servers : Included

#=====================================================================

#Browse file system

fnsysctl ls -la /data/lib/libips.bak

fnsysctl ls -la /data/lib/libgif.so

fnsysctl ls -la /data/lib/libiptcp.so

fnsysctl ls -la /data/lib/libipudp.so

fnsysctl ls -la /data/lib/libjepg.so

fnsysctl ls -la /var/.sslvpnconfigbk

fnsysctl ls -la /data/etc/wxd.conf

fnsysctl ls -la /flash

#=====================================================================