# Ævoryn

**Ævoryn Firewall** is a lightweight Linux firewall manager built with
Python and `nftables`.

## Features

-   Block / unblock IPv4 addresses
-   Block / unblock TCP ports
-   Block / unblock UDP ports
-   View firewall status and rules
-   View listening ports and active connections
-   System information
-   Save / load rules
-   Reset Ævoryn rules
-   Activity logging
-   Terminal startup banner with system information

## Requirements

-   Python 3
-   nftables
-   `ip`
-   `ss`
-   Root / sudo access

## Installation

### Debian / Ubuntu / Kali

``` bash
sudo apt update
sudo apt install python3 nftables iproute2
```

### Fedora

``` bash
sudo dnf install python3 nftables iproute
```

### Arch Linux

``` bash
sudo pacman -S python nftables iproute2
```

## Run On Linux

``` bash
sudo python3 Ævoryn.py
```

Or:

``` bash
chmod +x Ævoryn.py
sudo ./Ævoryn.py
```

## Run On Windows

``` bash
cmd > run as adminaitrator

python Ævoryn.py
```

## Menu

``` text
[1]  Firewall Status
[2]  System Scan
[3]  Listening Ports
[4]  Active Connections
[5]  Show Firewall Rules

[6]  Block IP
[7]  Unblock IP

[8]  Block TCP Port
[9]  Unblock TCP Port

[10] Block UDP Port
[11] Unblock UDP Port

[12] Save Rules
[13] Load Rules
[14] Reset Firewall

[0]  Exit
```

## Block / Unblock IP

Choose option `6` to block an IPv4 address and option `7` to unblock it.

Example:
p
``` text
Enter IPv4 address to BLOCK: 192.168.1.100
```

## Block / Unblock TCP Port

Choose option `8` to block a TCP port and option `9` to unblock it.

Example:

``` text
TCP port to BLOCK: 8080
```

## Block / Unblock UDP Port

Choose option `10` to block a UDP port and option `11` to unblock it.

Example:

``` text
UDP port to BLOCK: 5353
```

## View Rules

``` bash
sudo nft list table inet aevoryn
```

## Listening Ports

``` bash
ss -tulpn
```

## Active Connections

``` bash
ss -tunap
```

## Save / Load Rules

Use option `12` to save rules and option `13` to load them.

Saved configuration:

``` text
/etc/aevoryn.nft
```

## Reset

Choose option `14` and type:

``` text
RESET
```

## Logs

``` text
/var/log/aevoryn.log
```

## License

MIT License --- Copyright (c) 2026 0xP4r54
