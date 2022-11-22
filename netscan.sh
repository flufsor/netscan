#! /bin/sh

VLAN_MIN=1
VLAN_MAX=4094

# Check if the user is root
if [ $(id -u) -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Check if the user has provided a valid interface
if [ -z "$1" ]; then
  echo "Please provide an interface"
  exit 1
else
  if [ $(ip addr | grep -w $1 | wc -l) -eq 0 ]; then
    echo "Please provide a valid interface"
    exit 1
  fi
  interface=$1
fi

# ¨Prepare system for scanning
# Alter DHCP timeouts
sed -i  -e s/"#timeout 60"/"timeout 10"/ -e s/"#retry 60"/"retry 10"/ /etc/dhcp/dhclient.conf

echo "Starting Netscan on $interface"

# Set interface up
if [ $(cat /sys/class/net/$interface/operstate) = "down" ]; then
  echo "Setting $interface up"
  ip link set $interface up
  echo boo
fi

# Remove old DHCP lease
echo "Removing old DHCP lease"
dhclient -r $interface

# Request ip address from DHCP server
echo "Requesting ip address from DHCP server"
dhclient -4 $interface -v

# Check for successful DHCP request
ip=$(ip addr show $interface | grep "inet " | awk '{print $2}' | cut -d/ -f1)

if [ -z "$ip" ]; then
  echo "Could not get ip address from DHCP server"
  exit 1
else
  gateway=$(ip route show 0.0.0.0/0 dev $interface | cut -d\  -f3)
  echo "Ip: $ip"
  echo "Gateway: $gateway"
fi

# Ping test gateway
if ping -q -c 1 -W 1 $gateway >/dev/null; then
  echo "IPv4 is up"
else
  echo "IPv4 is down"
fi

# Ping test google.com
if ping -q -c 1 -W 1 www.google.com >/dev/null; then
  echo "Internet connectivity is up"
else
  echo "Internet connectivity is down"
fi

# Restore Files to original state
sed -i  -e s/"timeout 10"/"#timeout 60"/ -e s/"retry 10"/"#retry 60"/ /etc/dhcp/dhclient.conf
