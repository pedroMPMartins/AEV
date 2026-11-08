# snmpwalk / snmpget

`snmpwalk` and `snmpget` are part of the Net-SNMP suite. They are used to query devices running SNMP (Simple Network Management Protocol), typically over UDP. In network security and CTFs, SNMP is frequently inspected to leak system descriptions, network interfaces, usernames, running processes, or confidential enterprise variables.


## Basic Concepts

- **OID (Object Identifier):** A dotted-numerical hierarchy (e.g., `1.3.6.1.2.1.1.1.0`) pointing to a specific variable or subtree in the MIB (Management Information Base).
- **Community String:** Acts as a cleartext password. The default read-only community is almost always `public`.
- **SNMP Version:** Most modern legacy setups use SNMPv2c (`-v2c`) or SNMPv1 (`-v1`).


## 1. Querying a Specific OID (`snmpget`)

`snmpget` requests the value of a single, specific OID. For example, `1.3.6.1.2.1.1.1.0` corresponds to `sysDescr` (system description):

```bash
snmpget -v2c -c public 10.110.3.72:8024 1.3.6.1.2.1.1.1.0
```

Flags:
- `-v2c`: Uses SNMP version 2c.
- `-c public`: Sets the community string to `public`.
- `<IP>:<PORT>`: Target address and custom port (default is UDP 161).
- `<OID>`: The exact identifier to query.


## 2. Walking an OID Subtree (`snmpwalk`)

Instead of querying one variable at a time, `snmpwalk` uses repeated `GETNEXT` requests to traverse the entire MIB tree and print all accessible values:

```bash
# Walk from the default subtree
snmpwalk -v2c -c public 10.110.3.72:8024

# Walk from the root (.1)
snmpwalk -v2c -c public 10.110.3.72:8024 .1
```

If successful, this will dump system information, hostname, network interfaces, uptime, and any custom enterprise OIDs (under `1.3.6.1.4.1`).


## 3. Packet-Level Debugging (`-d`)

Sometimes in CTFs, challenge servers implement custom or slightly broken SNMP responders that return non-standard PDUs. Standard `snmpwalk` might complain and abort with errors like:

```
snmpwalk: Protocol error (Expected RESPONSE-PDU but got SET-PDU)
```

To see the raw UDP packets sent and received (both in hex and ASCII), pass the `-d` flag:

```bash
snmpwalk -d -v2c -c public 10.110.3.72:8024 .1
```

Example output (from Port 8024):
```
Sending 36 bytes to UDP: [10.110.3.72]:8024->[0.0.0.0]:45350
0000: 30 22 02 01  01 04 06 70  75 62 6C 69  63 A1 15 02    0".....public...
0016: 04 3C 4F 69  73 02 01 00  02 01 00 30  07 30 05 06    .<Ois......0.0..
0032: 01 01 05 00                                           ....

Received 90 byte packet from UDP: [10.110.3.72]:8024->[0.0.0.0]:45350
0000: 30 58 02 01  01 04 06 70  75 62 6C 69  63 A3 4B 02    0X.....public.K.
0016: 04 3C 4F 69  73 02 01 00  02 01 00 30  3D 30 3B 06    .<Ois......0=0;.
0032: 08 2B 06 01  02 01 01 01  00 04 2F 4C  69 6E 75 78    .+......../Linux
0048: 20 6C 61 62  2D 68 6F 73  74 20 36 2E  31 2E 30 2D     lab-host 6.1.0-
0064: 31 38 20 23  31 20 53 4D  50 20 78 38  36 5F 36 34    18 #1 SMP x86_64
0080: 20 47 4E 55  2F 4C 69 6E  75 78                        GNU/Linux

snmpwalk: Protocol error (Expected RESPONSE-PDU but got SET-PDU)
```

The `-d` output confirms that the server is alive and actively replying with real system data (`/Linux lab-host 6.1.0-18 #1 SMP x86_64 GNU/Linux`), even though the client threw an error. This packet dump can then be used to reconstruct raw UDP queries to walk the remaining tree.
