# Task 1


## 1. How many hosts are there on 10.110.3.0/24? Which addresses answer, and what do you think each one is? (Hint: not all of them are challenges.)

Ran:
```bash
nmap -sn 10.110.3.0/24
```

And got this output:
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

There are 4 active hosts out of the 256 possible IP addresses in the `10.110.3.0/24` subnet.

These addresses answer:
- `10.110.3.1`
- `10.110.3.2`
- `10.110.3.4`
- `10.110.3.72`


To find out which each of them do, I ran this:
```bash
nmap -sV -p- <IP>
```

These where the outputs for each of them.

**10.110.3.1**:
```
s12@s12:~$ nmap -sV -p- 10.110.3.4
Starting Nmap 7.95 ( https://nmap.org ) at 2026-10-14 10:38 UTC
Nmap scan report for 10.110.3.4
Host is up (0.00034s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT     STATE SERVICE        VERSION
22/tcp   open  ssh            OpenSSH 10.0p2 Debian 7+deb13u4 (protocol 2.0)
111/tcp  open  rpcbind        2-4 (RPC #100000)
3128/tcp open  http           Proxmox Virtual Environment REST API 3.0
8006/tcp open  wpl-analytics?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8006-TCP:V=7.95%I=7%D=10/14%Time=6ACF5BA9%P=x86_64-pc-linux-gnu%r(H
SF:TTPOptions,D7,"HTTP/1\.0\x20501\x20method\x20'OPTIONS'\x20not\x20availa
SF:ble\r\nCache-Control:\x20max-age=0\r\nConnection:\x20close\r\nDate:\x20
SF:Wed,\x2014\x20Oct\x202026\x2010:38:33\x20GMT\r\nPragma:\x20no-cache\r\n
SF:Server:\x20pve-api-daemon/3\.0\r\nExpires:\x20Wed,\x2014\x20Oct\x202026
SF:\x2010:38:33\x20GMT\r\n\r\n")%r(RTSPRequest,E3,"HTTP/1\.0\x20400\x20bad
SF:\x20request\r\nCache-Control:\x20max-age=0\r\nConnection:\x20close\r\nD
SF:ate:\x20Wed,\x2014\x20Oct\x202026\x2010:38:33\x20GMT\r\nPragma:\x20no-c
SF:ache\r\nServer:\x20pve-api-daemon/3\.0\r\nContent-Length:\x2011\r\nExpi
SF:res:\x20Wed,\x2014\x20Oct\x202026\x2010:38:33\x20GMT\r\n\r\nbad\x20requ
SF:est")%r(Help,E3,"HTTP/1\.0\x20400\x20bad\x20request\r\nCache-Control:\x
SF:20max-age=0\r\nConnection:\x20close\r\nDate:\x20Wed,\x2014\x20Oct\x2020
SF:26\x2010:38:48\x20GMT\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-daem
SF:on/3\.0\r\nContent-Length:\x2011\r\nExpires:\x20Wed,\x2014\x20Oct\x2020
SF:26\x2010:38:48\x20GMT\r\n\r\nbad\x20request")%r(TerminalServerCookie,E3
SF:,"HTTP/1\.0\x20400\x20bad\x20request\r\nCache-Control:\x20max-age=0\r\n
SF:Connection:\x20close\r\nDate:\x20Wed,\x2014\x20Oct\x202026\x2010:38:48\
SF:x20GMT\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-daemon/3\.0\r\nCont
SF:ent-Length:\x2011\r\nExpires:\x20Wed,\x2014\x20Oct\x202026\x2010:38:48\
SF:x20GMT\r\n\r\nbad\x20request")%r(Kerberos,E3,"HTTP/1\.0\x20400\x20bad\x
SF:20request\r\nCache-Control:\x20max-age=0\r\nConnection:\x20close\r\nDat
SF:e:\x20Wed,\x2014\x20Oct\x202026\x2010:38:48\x20GMT\r\nPragma:\x20no-cac
SF:he\r\nServer:\x20pve-api-daemon/3\.0\r\nContent-Length:\x2011\r\nExpire
SF:s:\x20Wed,\x2014\x20Oct\x202026\x2010:38:48\x20GMT\r\n\r\nbad\x20reques
SF:t")%r(LPDString,E3,"HTTP/1\.0\x20400\x20bad\x20request\r\nCache-Control
SF::\x20max-age=0\r\nConnection:\x20close\r\nDate:\x20Wed,\x2014\x20Oct\x2
SF:02026\x2010:38:58\x20GMT\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-d
SF:aemon/3\.0\r\nContent-Length:\x2011\r\nExpires:\x20Wed,\x2014\x20Oct\x2
SF:02026\x2010:38:58\x20GMT\r\n\r\nbad\x20request")%r(LDAPSearchReq,E3,"HT
SF:TP/1\.0\x20400\x20bad\x20request\r\nCache-Control:\x20max-age=0\r\nConn
SF:ection:\x20close\r\nDate:\x20Wed,\x2014\x20Oct\x202026\x2010:38:58\x20G
SF:MT\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-daemon/3\.0\r\nContent-
SF:Length:\x2011\r\nExpires:\x20Wed,\x2014\x20Oct\x202026\x2010:38:58\x20G
SF:MT\r\n\r\nbad\x20request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 103.84 seconds
```

**10.110.3.2**:
```
s12@s12:~$ nmap -sV -p- 10.110.3.2
Starting Nmap 7.95 ( https://nmap.org ) at 2026-10-14 10:48 UTC
Nmap scan report for 10.110.3.2
Host is up (0.00023s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT     STATE SERVICE        VERSION
22/tcp   open  ssh            OpenSSH 10.0p2 Debian 7+deb13u4 (protocol 2.0)
111/tcp  open  rpcbind        2-4 (RPC #100000)
3128/tcp open  http           Proxmox Virtual Environment REST API 3.0
8006/tcp open  wpl-analytics?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8006-TCP:V=7.95%I=7%D=10/14%Time=6ACF5E31%P=x86_64-pc-linux-gnu%r(H
SF:TTPOptions,D7,"HTTP/1\.0\x20501\x20method\x20'OPTIONS'\x20not\x20availa
SF:ble\r\nCache-Control:\x20max-age=0\r\nConnection:\x20close\r\nDate:\x20
SF:Wed,\x2014\x20Oct\x202026\x2010:49:21\x20GMT\r\nPragma:\x20no-cache\r\n
SF:Server:\x20pve-api-daemon/3\.0\r\nExpires:\x20Wed,\x2014\x20Oct\x202026
SF:\x2010:49:21\x20GMT\r\n\r\n")%r(RTSPRequest,E3,"HTTP/1\.0\x20400\x20bad
SF:\x20request\r\nCache-Control:\x20max-age=0\r\nConnection:\x20close\r\nD
SF:ate:\x20Wed,\x2014\x20Oct\x202026\x2010:49:21\x20GMT\r\nPragma:\x20no-c
SF:ache\r\nServer:\x20pve-api-daemon/3\.0\r\nContent-Length:\x2011\r\nExpi
SF:res:\x20Wed,\x2014\x20Oct\x202026\x2010:49:21\x20GMT\r\n\r\nbad\x20requ
SF:est")%r(Help,E3,"HTTP/1\.0\x20400\x20bad\x20request\r\nCache-Control:\x
SF:20max-age=0\r\nConnection:\x20close\r\nDate:\x20Wed,\x2014\x20Oct\x2020
SF:26\x2010:49:36\x20GMT\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-daem
SF:on/3\.0\r\nContent-Length:\x2011\r\nExpires:\x20Wed,\x2014\x20Oct\x2020
SF:26\x2010:49:36\x20GMT\r\n\r\nbad\x20request")%r(TerminalServerCookie,E3
SF:,"HTTP/1\.0\x20400\x20bad\x20request\r\nCache-Control:\x20max-age=0\r\n
SF:Connection:\x20close\r\nDate:\x20Wed,\x2014\x20Oct\x202026\x2010:49:36\
SF:x20GMT\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-daemon/3\.0\r\nCont
SF:ent-Length:\x2011\r\nExpires:\x20Wed,\x2014\x20Oct\x202026\x2010:49:36\
SF:x20GMT\r\n\r\nbad\x20request")%r(Kerberos,E3,"HTTP/1\.0\x20400\x20bad\x
SF:20request\r\nCache-Control:\x20max-age=0\r\nConnection:\x20close\r\nDat
SF:e:\x20Wed,\x2014\x20Oct\x202026\x2010:49:36\x20GMT\r\nPragma:\x20no-cac
SF:he\r\nServer:\x20pve-api-daemon/3\.0\r\nContent-Length:\x2011\r\nExpire
SF:s:\x20Wed,\x2014\x20Oct\x202026\x2010:49:36\x20GMT\r\n\r\nbad\x20reques
SF:t")%r(LPDString,E3,"HTTP/1\.0\x20400\x20bad\x20request\r\nCache-Control
SF::\x20max-age=0\r\nConnection:\x20close\r\nDate:\x20Wed,\x2014\x20Oct\x2
SF:02026\x2010:49:46\x20GMT\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-d
SF:aemon/3\.0\r\nContent-Length:\x2011\r\nExpires:\x20Wed,\x2014\x20Oct\x2
SF:02026\x2010:49:46\x20GMT\r\n\r\nbad\x20request")%r(LDAPSearchReq,E3,"HT
SF:TP/1\.0\x20400\x20bad\x20request\r\nCache-Control:\x20max-age=0\r\nConn
SF:ection:\x20close\r\nDate:\x20Wed,\x2014\x20Oct\x202026\x2010:49:46\x20G
SF:MT\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-daemon/3\.0\r\nContent-
SF:Length:\x2011\r\nExpires:\x20Wed,\x2014\x20Oct\x202026\x2010:49:46\x20G
SF:MT\r\n\r\nbad\x20request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 103.77 seconds
```

**10.110.3.4**:
```
s12@s12:~$ nmap -sV -p- 10.110.3.4
Starting Nmap 7.95 ( https://nmap.org ) at 2026-10-14 10:38 UTC
Nmap scan report for 10.110.3.4
Host is up (0.00034s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT     STATE SERVICE        VERSION
22/tcp   open  ssh            OpenSSH 10.0p2 Debian 7+deb13u4 (protocol 2.0)
111/tcp  open  rpcbind        2-4 (RPC #100000)
3128/tcp open  http           Proxmox Virtual Environment REST API 3.0
8006/tcp open  wpl-analytics?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8006-TCP:V=7.95%I=7%D=10/14%Time=6ACF5BA9%P=x86_64-pc-linux-gnu%r(H
SF:TTPOptions,D7,"HTTP/1\.0\x20501\x20method\x20'OPTIONS'\x20not\x20availa
SF:ble\r\nCache-Control:\x20max-age=0\r\nConnection:\x20close\r\nDate:\x20
SF:Wed,\x2014\x20Oct\x202026\x2010:38:33\x20GMT\r\nPragma:\x20no-cache\r\n
SF:Server:\x20pve-api-daemon/3\.0\r\nExpires:\x20Wed,\x2014\x20Oct\x202026
SF:\x2010:38:33\x20GMT\r\n\r\n")%r(RTSPRequest,E3,"HTTP/1\.0\x20400\x20bad
SF:\x20request\r\nCache-Control:\x20max-age=0\r\nConnection:\x20close\r\nD
SF:ate:\x20Wed,\x2014\x20Oct\x202026\x2010:38:33\x20GMT\r\nPragma:\x20no-c
SF:ache\r\nServer:\x20pve-api-daemon/3\.0\r\nContent-Length:\x2011\r\nExpi
SF:res:\x20Wed,\x2014\x20Oct\x202026\x2010:38:33\x20GMT\r\n\r\nbad\x20requ
SF:est")%r(Help,E3,"HTTP/1\.0\x20400\x20bad\x20request\r\nCache-Control:\x
SF:20max-age=0\r\nConnection:\x20close\r\nDate:\x20Wed,\x2014\x20Oct\x2020
SF:26\x2010:38:48\x20GMT\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-daem
SF:on/3\.0\r\nContent-Length:\x2011\r\nExpires:\x20Wed,\x2014\x20Oct\x2020
SF:26\x2010:38:48\x20GMT\r\n\r\nbad\x20request")%r(TerminalServerCookie,E3
SF:,"HTTP/1\.0\x20400\x20bad\x20request\r\nCache-Control:\x20max-age=0\r\n
SF:Connection:\x20close\r\nDate:\x20Wed,\x2014\x20Oct\x202026\x2010:38:48\
SF:x20GMT\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-daemon/3\.0\r\nCont
SF:ent-Length:\x2011\r\nExpires:\x20Wed,\x2014\x20Oct\x202026\x2010:38:48\
SF:x20GMT\r\n\r\nbad\x20request")%r(Kerberos,E3,"HTTP/1\.0\x20400\x20bad\x
SF:20request\r\nCache-Control:\x20max-age=0\r\nConnection:\x20close\r\nDat
SF:e:\x20Wed,\x2014\x20Oct\x202026\x2010:38:48\x20GMT\r\nPragma:\x20no-cac
SF:he\r\nServer:\x20pve-api-daemon/3\.0\r\nContent-Length:\x2011\r\nExpire
SF:s:\x20Wed,\x2014\x20Oct\x202026\x2010:38:48\x20GMT\r\n\r\nbad\x20reques
SF:t")%r(LPDString,E3,"HTTP/1\.0\x20400\x20bad\x20request\r\nCache-Control
SF::\x20max-age=0\r\nConnection:\x20close\r\nDate:\x20Wed,\x2014\x20Oct\x2
SF:02026\x2010:38:58\x20GMT\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-d
SF:aemon/3\.0\r\nContent-Length:\x2011\r\nExpires:\x20Wed,\x2014\x20Oct\x2
SF:02026\x2010:38:58\x20GMT\r\n\r\nbad\x20request")%r(LDAPSearchReq,E3,"HT
SF:TP/1\.0\x20400\x20bad\x20request\r\nCache-Control:\x20max-age=0\r\nConn
SF:ection:\x20close\r\nDate:\x20Wed,\x2014\x20Oct\x202026\x2010:38:58\x20G
SF:MT\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-daemon/3\.0\r\nContent-
SF:Length:\x2011\r\nExpires:\x20Wed,\x2014\x20Oct\x202026\x2010:38:58\x20G
SF:MT\r\n\r\nbad\x20request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 103.84 seconds
```

**10.110.3.72**:
```
s12@s12:~$ nmap -sV -p- 10.110.3.72
Starting Nmap 7.95 ( https://nmap.org ) at 2026-10-14 11:00 UTC
Nmap scan report for 10.110.3.72
Host is up (0.00025s latency).
Not shown: 65504 closed tcp ports (conn-refused)
PORT     STATE    SERVICE     VERSION
22/tcp   open     ssh         OpenSSH 10.0p2 Debian 7+deb13u4 (protocol 2.0)
3000/tcp open     ppp?
5355/tcp filtered llmnr
8000/tcp open     tcpwrapped
8010/tcp open     http        Gunicorn
8011/tcp open     http        Gunicorn
8012/tcp open     http        Gunicorn
8013/tcp open     http        Gunicorn
8014/tcp open     http        Gunicorn
8015/tcp open     http        Gunicorn
8016/tcp open     http        Gunicorn
8017/tcp open     http        Gunicorn
8018/tcp open     http        Gunicorn
8019/tcp open     http        Gunicorn
8020/tcp open     http        Gunicorn
8021/tcp open     http        Gunicorn
8022/tcp open     http        Gunicorn
8023/tcp open     http        Gunicorn
8030/tcp open     http        Gunicorn
8031/tcp open     http        Gunicorn
8032/tcp open     http        Gunicorn
8033/tcp open     http        Gunicorn
8034/tcp open     http        Gunicorn
8035/tcp open     http        Gunicorn
8036/tcp open     http        Gunicorn
8037/tcp open     http        Gunicorn
8081/tcp open     http        Apache httpd 2.4.7 ((Ubuntu))
8082/tcp open     http        Apache httpd 2.4.25 ((Debian))
8083/tcp open     http        Apache httpd 2.4.7 ((Ubuntu))
8084/tcp open     http        Apache httpd 2.4.67 ((Debian))
9001/tcp open     tor-orport?
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3000-TCP:V=7.95%I=7%D=10/14%Time=6ACF60CC%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,1C48,"HTTP/1\.1\x20200\x20OK\r\nAccess-Control-Allow-Origin:\
SF:x20\*\r\nX-Content-Type-Options:\x20nosniff\r\nX-Frame-Options:\x20SAME
SF:ORIGIN\r\nFeature-Policy:\x20payment\x20'self'\r\nX-Recruiting:\x20/#/j
SF:obs\r\nAccept-Ranges:\x20bytes\r\nCache-Control:\x20public,\x20max-age=
SF:0\r\nLast-Modified:\x20Fri,\x2002\x20Oct\x202026\x2013:14:12\x20GMT\r\n
SF:ETag:\x20W/\"24b1-1a0fcc03ff0\"\r\nContent-Type:\x20text/html;\x20chars
SF:et=UTF-8\r\nContent-Length:\x209393\r\nVary:\x20Accept-Encoding\r\nDate
SF::\x20Wed,\x2014\x20Oct\x202026\x2011:00:28\x20GMT\r\nConnection:\x20clo
SF:se\r\n\r\n<!--\n\x20\x20~\x20Copyright\x20\(c\)\x202014-2026\x20Bjoern\
SF:x20Kimminich\x20&\x20the\x20OWASP\x20Juice\x20Shop\x20contributors\.\n\
SF:x20\x20~\x20SPDX-License-Identifier:\x20MIT\n\x20\x20-->\n\n<!doctype\x
SF:20html>\n<html\x20lang=\"en\"\x20data-beasties-container>\n<head>\n\x20
SF:\x20<meta\x20charset=\"utf-8\">\n\x20\x20<title>OWASP\x20Juice\x20Shop<
SF:/title>\n\x20\x20<meta\x20name=\"description\"\x20content=\"Probably\x2
SF:0the\x20most\x20modern\x20and\x20sophisticated\x20insecure\x20web\x20ap
SF:plication\">\n\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=dev
SF:ice-width,\x20initial-scale=1\">\n\x20\x20<link\x20rel=\"preconnect\"\x
SF:20href=\"htt")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnect
SF:ion:\x20close\r\n\r\n")%r(NCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\
SF:nConnection:\x20close\r\n\r\n")%r(HTTPOptions,EA,"HTTP/1\.1\x20204\x20N
SF:o\x20Content\r\nAccess-Control-Allow-Origin:\x20\*\r\nAccess-Control-Al
SF:low-Methods:\x20GET,HEAD,PUT,PATCH,POST,DELETE\r\nVary:\x20Access-Contr
SF:ol-Request-Headers\r\nContent-Length:\x200\r\nDate:\x20Wed,\x2014\x20Oc
SF:t\x202026\x2011:00:28\x20GMT\r\nConnection:\x20close\r\n\r\n")%r(RTSPRe
SF:quest,EA,"HTTP/1\.1\x20204\x20No\x20Content\r\nAccess-Control-Allow-Ori
SF:gin:\x20\*\r\nAccess-Control-Allow-Methods:\x20GET,HEAD,PUT,PATCH,POST,
SF:DELETE\r\nVary:\x20Access-Control-Request-Headers\r\nContent-Length:\x2
SF:00\r\nDate:\x20Wed,\x2014\x20Oct\x202026\x2011:00:28\x20GMT\r\nConnecti
SF:on:\x20close\r\n\r\n")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20Bad\x20Reques
SF:t\r\nConnection:\x20close\r\n\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port9001-TCP:V=7.95%I=7%D=10/14%Time=6ACF60CD%P=x86_64-pc-linux-gnu%r(N
SF:ULL,12,"What's\x20your\x20name\?\n")%r(GenericLines,24,"What's\x20your\
SF:x20name\?\nHello,\x20\r\nGoodbye\.\n")%r(GetRequest,32,"What's\x20your\
SF:x20name\?\nHello,\x20GET\x20/\x20HTTP/1\.0\r\nGoodbye\.\n")%r(SSLSessio
SF:nReq,25,"What's\x20your\x20name\?\nHello,\x20\x16\x03\nGoodbye\.\n")%r(
SF:TLSSessionReq,25,"What's\x20your\x20name\?\nHello,\x20\x16\x03\nGoodbye
SF:\.\n")%r(SSLv23SessionReq,1F,"What's\x20your\x20name\?\nHello,\x20\x80\
SF:x9e\x01\x03\x01\n")%r(JavaRMI,12,"What's\x20your\x20name\?\n")%r(Radmin
SF:,12,"What's\x20your\x20name\?\n")%r(mongodb,12,"What's\x20your\x20name\
SF:?\n")%r(tarantool,2D,"What's\x20your\x20name\?\nHello,\x20show\x20info\
SF:r\nGoodbye\.\n")%r(HTTPOptions,36,"What's\x20your\x20name\?\nHello,\x20
SF:OPTIONS\x20/\x20HTTP/1\.0\r\nGoodbye\.\n")%r(RTSPRequest,36,"What's\x20
SF:your\x20name\?\nHello,\x20OPTIONS\x20/\x20RTSP/1\.0\r\nGoodbye\.\n")%r(
SF:RPCCheck,12,"What's\x20your\x20name\?\n")%r(DNSVersionBindReqTCP,12,"Wh
SF:at's\x20your\x20name\?\n")%r(DNSStatusRequestTCP,12,"What's\x20your\x20
SF:name\?\n")%r(Help,28,"What's\x20your\x20name\?\nHello,\x20HELP\r\nGoodb
SF:ye\.\n")%r(TerminalServerCookie,24,"What's\x20your\x20name\?\nHello,\x2
SF:0\x03\nGoodbye\.\n")%r(Kerberos,23,"What's\x20your\x20name\?\nHello,\x2
SF:0\nGoodbye\.\n")%r(SMBProgNeg,12,"What's\x20your\x20name\?\n")%r(X11Pro
SF:be,12,"What's\x20your\x20name\?\n")%r(FourOhFourRequest,55,"What's\x20y
SF:our\x20name\?\nHello,\x20GET\x20/nice%20ports%2C/Tri%6Eity\.txt%2ebak\x
SF:20HTTP/1\.0\r\nGoodbye\.\n")%r(LPDString,2B,"What's\x20your\x20name\?\n
SF:Hello,\x20\x01default\nGoodbye\.\n")%r(LDAPSearchReq,25,"What's\x20your
SF:\x20name\?\nHello,\x200\x84\nGoodbye\.\n")%r(LDAPBindReq,12,"What's\x20
SF:your\x20name\?\n")%r(SIPOptions,3A,"What's\x20your\x20name\?\nHello,\x2
SF:0OPTIONS\x20sip:nm\x20SIP/2\.0\r\nGoodbye\.\n")%r(LANDesk-RC,12,"What's
SF:\x20your\x20name\?\n")%r(TerminalServer,12,"What's\x20your\x20name\?\n"
SF:)%r(NCP,12,"What's\x20your\x20name\?\n")%r(NotesRPC,12,"What's\x20your\
SF:x20name\?\n")%r(WMSRequest,12,"What's\x20your\x20name\?\n")%r(oracle-tn
SF:s,12,"What's\x20your\x20name\?\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 121.50 seconds
```


With this, here are my thoughts on what each host is:
- **10.110.3.1**: I belive this is the gateway, that handles network routing. 
- **10.110.3.2**: I think it is a Hypervisor, since this host is running (deduced) Promox virtualization services. In a lab setting, this is usually the underlying infrastructure hosting the virtual machines.
- **10.110.3.4**: same as the `10.110.3.2`.
- **10.110.3.72**: since hte infrastructure nodes are accounted for, `10.110.3.72` is likelly the actual challenge machine.


## 2. Build a **port → service → challenge** map for 10.110.3.72: which port belongs to which challenge name? Cross-check your map against DNS and against what CTFd lists.

Firstly, taking into account the output of the following command:
```bash
nmap -sV -p- 10.110.3.72
```
(See above)

We can determine the following:
- Port 22 is running SSH
- Port 3000 is running OWASP Juice Shop (we can infer from the HTML body).
- Ports 8010-8023 Gunicorn Python web servers, running independent applications.
- Ports 8081-8084 are several apache web servers running on different versions of Ubunto and Debian.
- Port 9001 has a custom program that is asking for my name.


Python code to attempt to get the titles of each service:
```bash
python3 -c '
import urllib.request, re
ports = list(range(8010, 8024)) + list(range(8030, 8038)) + [3000, 8081, 8082, 8083, 8084]
for p in ports:
    try:
        url = f"http://10.110.3.72:{p}"
        req = urllib.request.urlopen(url, timeout=2)
        html = req.read().decode("utf-8", errors="ignore")
        match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE)
        title = match.group(1).strip() if match else "No title tag"
        print(f"Port {p}: {title}")
    except Exception as e:
        print(f"Port {p}: (offline or not HTTP)")
'
```

This is the output:
```
Port 8010: No title tag
Port 8011: No title tag
Port 8012: No title tag
Port 8013: No title tag
Port 8014: No title tag
Port 8015: No title tag
Port 8016: No title tag
Port 8017: No title tag
Port 8018: Acme Corp
Port 8019: No title tag
Port 8020: No title tag
Port 8021: Lab recipes
Port 8022: Bench log
Port 8023: Team card
Port 8030: Staff Portal
Port 8031: TechBazaar Search
Port 8032: PhotoVault
Port 8033: DropLite
Port 8034: The Daily Byte
Port 8035: Guestbook
Port 8036: Linkly
Port 8037: TransferOps Console
Port 3000: OWASP Juice Shop
Port 8081: bWAPP - Login
Port 8082: Login :: Damn Vulnerable Web Application (DVWA) v1.10 *Development*
Port 8083: No title tag
Port 8084: (offline or not HTTP)
```


I started manual checking. For each one, I found the following:















--------------------------------------------------


For some reason, it seems like a lot of ports were disconected (we probably should not be messing with them right now).

Here are the ones that are currently open:
```
PORT     STATE    SERVICE     VERSION
22/tcp   open     ssh         OpenSSH 10.0p2 Debian 7+deb13u4 (protocol 2.0)
3000/tcp open     ppp?
5355/tcp filtered llmnr
8000/tcp open     tcpwrapped
8010/tcp open     http        Gunicorn
8011/tcp open     http        Gunicorn
8012/tcp open     http        Gunicorn
8013/tcp open     http        Gunicorn
8014/tcp open     http        Gunicorn
8015/tcp open     http        Gunicorn
8016/tcp open     http        Gunicorn
8017/tcp open     http        Gunicorn
8018/tcp open     http        Gunicorn
8019/tcp open     http        Gunicorn
8020/tcp open     http        Gunicorn
8081/tcp open     http        Apache httpd 2.4.7 ((Ubuntu))
8082/tcp open     http        Apache httpd 2.4.25 ((Debian))
8083/tcp open     http        Apache httpd 2.4.7 ((Ubuntu))
8084/tcp open     http        Apache httpd 2.4.67 ((Debian))
9001/tcp open     tor-orport?

```

I will continue manually inspecting them.






------------------------
