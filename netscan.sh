#!/usr/bin/env bash
# title         : netscan.sh
# description   : A Network port scanner for linux.
# author        : Tom Goedemé https://github.com/flufsor
# usage         : ./netscan.sh -t <interface> [-i <vlan scan time>]
# ======================================================================================================================

TCPDUMP_TIMEOUT=60
IPFILTER='((192|172|10){1,3}\.){1}([0-9]{1,3}\.){2}(?!255)([0-9]{1,3})'
PREFIXFILTER='((192|172|10){1,3}\.){1}([0-9]{1,3}\.){2}'

function ShowHelp()
{
      echo "Usage: $0 [Options]"
      echo "Options:"
      echo "  -c  Cleanup after scan"
      echo "  -i  Interface to scan"
      echo "  -l  scan for LLDP hosts"
      echo "  -t  Timeout for tcpdump"
      echo "  -h  Show this help"
}

# Check if the user is root
if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

while getopts ':cli:t:h' opt; do
  case "$opt" in
    c)
      CLEANUP=true;
      ;;
    i)
      if [[ ! -d /sys/class/net/${OPTARG} ]]; then
        echo "Please provide a valid interface"
        exit 1
      fi
      interface=$OPTARG
      interfaceShort=$(echo "$interface" | cut -c -6) # Some interfaces are too long
      ;;
    l)
      LLDP=true;
      ;;
    t)
      TCPDUMP_TIMEOUT=$OPTARG
      ;;
    h)
      ShowHelp
      exit 0
      ;;
    *)
      echo -e "Invalid command option: -$OPTARG \n"
      ShowHelp
      exit 1
      ;;
  esac
done
shift "$(("$OPTIND" -1))"

if [ -z "$interface" ]; then
  echo -e "Invalid command option.\nUsage: $(basename "$0") -i <interface>"
  exit 1
fi

echo "Starting Netscan on $interface"

# Set interface up
if [ "$(cat "/sys/class/net/$interface/operstate")" = "down" ]; then
  echo "Setting $interface up"
  ip link set "$interface" up
else 
  echo "interface $interface is already up"
fi

# Scan for vlans
echo "Starting VLAN scan for $TCPDUMP_TIMEOUT seconds"
timeout "$TCPDUMP_TIMEOUT" tcpdump -nnt -e vlan -i "$interface" > "scans/tcpdump-$interface.log" 2>/dev/null
mapfile -t vlans < <(grep -oP '(?:vlan )([0-9])+' "scans/tcpdump-$interface.log"  | awk '{print $2}' | sort -nu)

if [ ${#vlans[@]} -ne 0 ]; then # Check if there are any vlans
  echo "vlans found:"

  for vlan in "${vlans[@]}"; do
    echo -e "\t-VLAN: $vlan"
  done

  echo -e "\nRequesting IP addresses for vlans"
  for vlan in "${vlans[@]}"; do
    echo -e "Scanning Vlan: $vlan"

    # Set interface up
    ip link add link "$interface" name "$interfaceShort.$vlan" type vlan id "$vlan" >/dev/null 2>&1
    # Requst DHCP address
    timeout 2 dhclient -cf ./dhclient.conf -d -1 "$interfaceShort.$vlan" &>/dev/null
    # Check for successful DHCP request
    ip=$(ip addr show "$interfaceShort.$vlan" | grep "inet " | awk '{print $2}')

    if [ -z "$ip" ]; then
      echo -e "\tCould not get ip address from DHCP server"
      echo -e "\tTrying to find manual address"

      # Trying to find a manual address
      FOUND_HOSTS=$(grep "vlan $vlan" "scans/tcpdump-$interface.log" | grep -Po "$IPFILTER" | sort -u)
      PREFIX=$(echo "$FOUND_HOSTS" | grep -Po "$PREFIXFILTER" | sort -u)
      FIRST_HOST=$(echo "$FOUND_HOSTS" | head -n 1)

      for IP_OCTET in {20..234}; do
        if echo "$PREFIX$IP_OCTET" | grep -qv "$FOUND_HOSTS"; then
          IP="$PREFIX$IP_OCTET"
          for NETMASK in {24,16,8}; do
            ip addr add "$IP/$NETMASK" dev "$interfaceShort.$vlan"
            ip link set "$interfaceShort.$vlan" up
            # Test connection
            if ping -c 1 "$FIRST_HOST" >/dev/null 2>&1; then
              echo -e "\tFound manual address: $IP/$NETMASK"
              break
            fi
          done
          break
        fi
      done
      echo -e "\tCould not find manual address"
    else
      echo -e "\tGot DHCP ip: $ip"
    fi

    if [ "$LLDP" == true ]; then      # Scan for LLDP hosts
      echo -e "\tScanning for LLDP hosts"
      lldpcli show neighbors ports "$interfaceShort.$vlan" > "scans/lldp-$interfaceShort.$vlan.log"
      mapfile -t lldp_neighbors < "scans/lldp-$interfaceShort.$vlan.log"

      for line in "${lldp_neighbors[@]}"; do
        mac=$(echo "$line" | grep -oP 'ChassisID: mac \K.+')
        ip=$(echo "$line" | grep -oP 'MgmtIP: \K.+')

        [[ -n $mac ]] && [[ -n $ip ]] && echo -e "\t\t$mac $ip"
      done
    fi

  done
else # No vlans found
  echo "No vlans found, trying native VLAN"
  timeout 2 dhclient -cf ./dhclient.conf -d -1 "$interface" &>/dev/null
  ip=$(ip addr show "$interface" | grep "inet " | awk '{print $2}')
  #TODO: Check if ip is empty and try static ip

  if [ "$LLDP" == true ]; then      # Scan for LLDP hosts
    echo -e "\tScanning for LLDP hosts"
    lldpcli show neighbors ports "$interface" > "scans/lldp-$interface.log"
    mapfile -t lldp_neighbors < "scans/lldp-$interface.log"
    for line in "${lldp_neighbors[@]}"; do
      mac=$(echo "$line" | grep -oP 'ChassisID: mac \K.+')
      ip=$(echo "$line" | grep -oP 'MgmtIP: \K.+')

      [[ -n $mac ]] && [[ -n $ip ]] && echo -e "\t\t$mac $ip"
    done

  fi
fi

if [ "$CLEANUP" == true ]; then
  echo "Cleaning up"
  ip link set "$interface" down
  if [ ${#vlans[@]} -ne 0 ]; then
    for vlan in "${vlans[@]}"; do
      ip link delete "$interfaceShort.$vlan"
    done
  fi
fi