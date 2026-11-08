# nmap

nmap is probably one of the most important tools, since it is usually used in the beggining to probe things.


## Check a range to see what is online

If you want to just check a range of ips to see what is online, you can run the following command:
```bash
nmap -sn 10.110.3.0/24
```

The flag `-sn` disables the port scanning, only trying to understand if the host itself is alive.
`10.110.3.0\24` is the range you want to scan.

The output of that will then be something like this:
```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-10-14 10:35 UTC
Nmap scan report for 10.110.3.1
Host is up (0.00055s latency).
Nmap scan report for 10.110.3.2
Host is up (0.00041s latency).
Nmap scan report for 10.110.3.4
Host is up (0.00037s latency).
Nmap scan report for 10.110.3.72
Host is up (0.0015s latency).
Nmap done: 256 IP addresses (4 hosts up) scanned in 2.91 seconds 
```

## Scan your current network

You need to find the network you are residing, with something like `ip a` or `ipconfig`. If for some reason those are not installed, you can get your machine's IP address with `hostname -i` (gets the machine's configured hostname, may not be the real one) or `hostname -I` (directly inspects network to get all the configured, routable IP addresses) and then from there try to guess what your network is.

For example, I ran `ip a`, `hostname -i` and `hostname -I` and got this output:
```
i@i:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: enp0s31f6: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state DOWN group default qlen 1000
    link/ether 48:2a:e3:2c:ab:d2 brd ff:ff:ff:ff:ff:ff
3: wwan0: <POINTOPOINT,NOARP> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/none 
4: wlp2s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 48:f1:7f:1e:7f:17 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.81/24 brd 192.168.1.255 scope global dynamic noprefixroute wlp2s0
       valid_lft 3331sec preferred_lft 3331sec
    inet6 2001:818:c39f:f700:bf31:c97d:751e:ba9f/64 scope global temporary dynamic 
       valid_lft 86367sec preferred_lft 43167sec
    inet6 2001:818:c39f:f700:5b4b:4be7:d3d3:19f5/64 scope global dynamic mngtmpaddr noprefixroute 
       valid_lft 86367sec preferred_lft 43167sec
    inet6 fe80::36f9:e023:a151:8f6f/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
5: virbr0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default qlen 1000
    link/ether 52:54:00:68:97:25 brd ff:ff:ff:ff:ff:ff
    inet 192.168.122.1/24 brd 192.168.122.255 scope global virbr0
       valid_lft forever preferred_lft forever
6: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether ca:77:d4:a2:64:96 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
i@i:~$ ipconfig
Command 'ipconfig' not found, did you mean:
  command 'iconfig' from deb ipmiutil (3.1.9-3)
  command 'ifconfig' from deb net-tools (2.10-0.1ubuntu4.4)
  command 'iwconfig' from deb wireless-tools (30~pre9-13.1ubuntu4)
  command 'hipconfig' from deb hipcc (5.2.3-12)
Try: sudo apt install <deb name>
i@i:~$ hostname -i
127.0.1.1
i@i:~$ hostname -I
192.168.1.81 192.168.122.1 172.17.0.1 2001:818:c39f:f700:bf31:c97d:751e:ba9f 2001:818:c39f:f700:5b4b:4be7:d3d3:19f5 
```

The network is in the interface `wlp2s0` (Wi-Fi). So my current IP is `192.168.1.81`, and the network I am on is `192.168.1.0/24` (we know it is `/24`, because it says this `192.168.1.81/24`).

So to scan my current network, I would do:
```bash
# If I just to see the hosts that are up
nmap -sn 192.168.1.0/24
```


## Scan a specific IP

You can scan all the ports of a specific IP address and try to document the versions and services that are running in each of them with the following command:
```bash
nmap -sV -p- <IP>
```

Where the flag `-sV` tells nmap to try to understand what is running in each port.
The flag `-p-` tells nmap to scan all ports to understand which ones are active.
`<IP>` is the IP you want to scan.


## Really really intrusive scans

To make a really really intrusive scan to some target or a range, I can do this:
```bash
sudo nmap -A -sV --version-intensity 7 -O --osscan-guess -p- -T4 --script vuln,vulners -oA full_intrusive_scan <target>
```

This is what each component does:
*   **`-A` (Aggressive Scan)**: This is the cornerstone. It enables OS detection (`-O`), service version detection (`-sV`), default script scanning (`-sC`), and traceroute, giving you a huge amount of information in one go.
*   **`-sV --version-intensity 7`**: While `-A` includes `-sV`, explicitly setting the **version intensity** to a higher value (0-9) makes Nmap send more probes to confirm the exact software version. This is crucial for accurate CVE mapping later.
*   **`-O --osscan-guess`**: Forces Nmap to make its best guess at the operating system, even if it isn't a perfect match, which is useful when a host doesn't respond perfectly to fingerprinting.
*   **`-p-`**: Scans **all 65,535 TCP ports** instead of just the top 1000. This is the most intrusive port scan and ensures you don't miss a service running on a non-standard port.
*   **`-T4`**: Sets the timing template to "Aggressive," which speeds up the scan significantly. Be careful, as this can overwhelm older or fragile devices.
*   **`--script vuln,vulners`**: This is the CVE engine. It runs NSE scripts from two categories:
    *   **`vuln`**: A broad category of scripts that check for specific known vulnerabilities and misconfigurations.
    *   **`vulners`**: A powerful script that takes the detected service versions and cross-references them against the extensive **Vulners** database (and other sources) to return CVE IDs and CVSS scores.
*   **`-oA full_intrusive_scan`**: Saves the output in all three major formats (normal, XML, and grepable) with the base name `full_intrusive_scan` for easy reporting and parsing later.
