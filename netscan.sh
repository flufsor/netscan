#!/usr/bin/env bash
# title         : netscan.sh
# description   : A Network port scanner for linux.
# author        : Tom Goedemé https://github.com/flufsor
# usage         : ./netscan.sh -i <interface> [-t <vlan scan time>]
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
      echo "  -t  Timeout for tcpdump"
      echo "  -h  Show this help"
}

# Check if the user is root
if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

while getopts ':ci:rt:h' opt; do
  case "$opt" in
    c)
      CLEANUP=true;
      ;;
    i)
      if [[ ! -d /sys/class/net/${OPTARG} ]]; then
        echo "Please provide a valid interface"
        exit 1
      fi
      INTERFACE=$OPTARG
      INTERFACESHORT=$(echo "$INTERFACE" | cut -c -6) # Some interfaces are too long
      ;;
    r)
      TARRESULTS=true;
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

if [ -z "$INTERFACE" ]; then
  echo -e "Invalid command option.\nUsage: $(basename "$0") -i <interface>"
  exit 1
fi

echo "Starting Netscan on $INTERFACE"

# Set interface up
if [ "$(cat "/sys/class/net/$INTERFACE/operstate")" = "down" ]; then
  echo "Setting $INTERFACE up"
  ip link set "$INTERFACE" up
else 
  echo "Interface $INTERFACE is already up"
fi

#  Set LLDPD to enable cdp and listen only
if ! grep -q 'DAEMON_ARGS="-c -s -e"' "/etc/default/lldpd"; then
    echo 'DAEMON_ARGS="-c -s -e"' >> "/etc/default/lldpd"
fi

# Start LLDPD
systemctl restart lldpd

# Scan for VLANs
echo "Starting VLAN scan for $TCPDUMP_TIMEOUT seconds"
timeout "$TCPDUMP_TIMEOUT" tcpdump -nnt -e vlan -i "$INTERFACE" > "scans/tcpdump-$INTERFACE.log" 2>/dev/null
mapfile -t vlans < <(grep -oP '(?:vlan )([0-9])+' "scans/tcpdump-$INTERFACE.log"  | awk '{print $2}' | sort -nu)

if [ ${#vlans[@]} -ne 0 ]; then
  echo "VLANs found:"

  for vlan in "${vlans[@]}"; do
    echo -e "\t-VLAN: $vlan"
  done

  echo -e "\nRequesting IP addresses for VLANs"
  for vlan in "${vlans[@]}"; do
    echo -e "\nScanning Vlan: $vlan"

    # Set interface up
    ip link add link "$INTERFACE" name "$INTERFACESHORT.$vlan" type vlan id "$vlan" >/dev/null 2>&1
    # Requst DHCP address
    timeout 2 dhclient -cf ./dhclient.conf -d -1 "$INTERFACESHORT.$vlan" &>/dev/null
    # Check for successful DHCP request
    IP=$(ip addr show "$INTERFACESHORT.$vlan" | grep "inet " | awk '{print $2}')

    if [ -z "$IP" ]; then
      echo -e "\tCould not get ip address from DHCP server"
      echo -e "\tTrying to find manual address"

      # Trying to find a manual address
      FOUND_HOSTS=$(grep "vlan $vlan" "scans/tcpdump-$INTERFACE.log" | grep -Po "$IPFILTER" | sort -u)
      PREFIX=$(echo "$FOUND_HOSTS" | grep -Po "$PREFIXFILTER" | sort -u)
      FIRST_HOST=$(echo "$FOUND_HOSTS" | head -n 1)

      for IP_LASTOCTET in {20..234}; do
        if echo "$PREFIX$IP_LASTOCTET" | grep -qv "$FOUND_HOSTS"; then
          IP="$PREFIX$IP_LASTOCTET"
          for NETMASK in {24,16,8}; do
            ip addr add "$IP/$NETMASK" dev "$INTERFACESHORT.$vlan"
            ip link set "$INTERFACESHORT.$vlan" up
            # Test connection
            if ping -c 1 "$FIRST_HOST" >/dev/null 2>&1; then
              echo -e "\tFound manual address: $IP/$NETMASK"
              break
            fi
          done
          break
        fi
      done

      if [ -z "$IP" ]; then
        echo -e "\tCould not find manual address"
      fi
    else
      echo -e "\tGot DHCP ip: $IP"
    fi
  done
else
  echo "No VLANs found, trying native VLAN"
  timeout 2 dhclient -cf ./dhclient.conf -d -1 "$INTERFACE" &>/dev/null
  INTIP=$(ip addr show "$INTERFACE" | grep "inet " | awk '{print $2}')

  if [ -z "$INTIP" ]; then
    echo -e "\tCould not get ip address from DHCP server"
    echo -e "\tTrying to find manual address"

    # Trying to find a manual address
    FOUND_HOSTS=$(grep -Po "$IPFILTER" "./scans/tcpdump-$INTERFACE.log" | sort -u)
    PREFIX=$(echo "$FOUND_HOSTS" | grep -Po "$PREFIXFILTER" | sort -u)
    FIRST_HOST=$(echo "$FOUND_HOSTS" | head -n 1)

    for INTIP_LASTOCTET in {20..234}; do
      if echo "$PREFIX$INTIP_LASTOCTET" | grep -qv "$FOUND_HOSTS"; then
        IP="$PREFIX$INTIP_LASTOCTET"
        for INTNETMASK in {24,16,8}; do
          ip addr add "$INTIP/$INTNETMASK" dev "$INTERFACE"
          # Test connection
          if ping -c 1 "$FIRST_HOST" >/dev/null 2>&1; then
            echo -e "\tFound manual address: $INTIP/$INTNETMASK"
            break
          fi
        done
        break
      fi
    done

    if [ -z "$INTIP" ]; then
      echo -e "\tCould not find manual address"
    fi
  else
    echo -e "\tGot DHCP ip: $INTIP"
  fi
fi

echo ""

# Check LLDPD Scans
lldpcli show neighbors ports "$INTERFACE" > "./scans/lldp-$INTERFACE.log" 2>/dev/null
LLDPMACS=$(grep -oE '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' scans/lldp-"$INTERFACE".log | sort -u)
if [ -z "$LLDPMACS" ]; then
  echo -e "\nNo LLDP servers found"
else 
  echo -e "\nFound $(echo "$LLDPMACS" | wc -l) LLDP servers"
  for MAC in $LLDPMACS; do
    echo -e "\t- $MAC"

    awk -v MAC="$MAC" '
    $0 ~ MAC {found=1}
    found && $0 ~ /SysName: / {sysname=$2}
    found && $0 ~ /SysDescr: / {sysdescr=substr($0, index($0, $2))}
    found && $0 ~ /MgmtIP: / {mgmtip=$2}
    sysname && sysdescr && mgmtip {
        printf "\t\tSysName: %s\n", sysname;
        printf "\t\tSysDescr: %s\n", sysdescr;
        printf "\t\tMgmtIP: %s\n\n", mgmtip;
        exit;
    }
    ' "./scans/lldp-$INTERFACE.log"
  done 
fi
echo ""

# Tar results
if [ "$TARRESULTS" == true ]; then
  date=$(date +"%Y-%m-%d_%H-%M-%S")
  file="./scans/netscan-$INTERFACE-$date.tar.gz"
  tar -czf "$file" ./results/{tcpdump,lldp}-"$INTERFACE".log
  echo -e "Results are in $file\n\n"
fi

# Stop lldpd
systemctl stop lldpd

if [ "$CLEANUP" == true ]; then
  echo "Cleaning up"
  ip link set "$INTERFACE" down

  if [ -z ${INTIP+x} ]; then
    ip addr del "$INTIP" dev "$INTERFACE" 2>/dev/null
  fi

  for vlan in "${vlans[@]}"; do
    ip link delete "$INTERFACESHORT.$vlan"
  done
fi