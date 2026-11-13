# Log format research notes (sources: vendor docs, verified 2026-11-13)

## Palo Alto PAN-OS TRAFFIC (CSV, syslog-wrapped)
Order (0-idx): FUTURE_USE, Receive Time, Serial Number, Type, Threat/Content Type(subtype),
FUTURE_USE, Generated Time, Source Address, Destination Address, NAT Source IP, NAT Destination IP,
Rule Name, Source User, Destination User, Application, Virtual System, Source Zone, Destination Zone,
Inbound Interface, Outbound Interface, Log Action, FUTURE_USE, Session ID, Repeat Count, Source Port,
Destination Port, NAT Source Port, NAT Destination Port, Flags, Protocol, Action, Bytes, Bytes Sent,
Bytes Received, Packets, Start Time, Elapsed Time, Category, FUTURE_USE, Sequence Number, Action Flags,
Source Country(Location), Destination Country(Location), FUTURE_USE, Packets Sent, Packets Received,
Session End Reason, ...(+device group hierarchy etc; we stop at Session End Reason)
src: docs.paloaltonetworks.com traffic-log-fields

## PAN-OS THREAT (CSV)
FUTURE_USE, Receive Time, Serial Number, Type, Subtype, FUTURE_USE, Generated Time, Source IP,
Destination IP, NAT Source IP, NAT Destination IP, Rule Name, Source User, Destination User,
Application, Virtual System, Source Zone, Destination Zone, Ingress Interface, Egress Interface,
Log Forwarding Profile, FUTURE_USE, Session ID, Repeat Count, Source Port, Destination Port,
NAT Source Port, NAT Destination Port, Flags, Protocol, Action, Miscellaneous(URL/filename),
Threat ID, Category, Severity, Direction, Sequence Number, Action Flags, Source Location,
Destination Location, FUTURE_USE, Content Type
ThreatID ranges: 30000-44999 vuln exploit, 10000-19999 spyware phone-home, 8000-8099 scan.
Subtype: vulnerability, spyware, virus, url, file, scan, flood, data

## FortiGate (key=value, syslog)
date=YYYY-MM-DD time=HH:MM:SS devname="FW" devid="FG..." logid="..." type="traffic" subtype="forward"
level="notice" vd="root" eventtime=<ns> srcip= srcport= srcintf="port1" dstip= dstport= dstintf="wan1"
sessionid= proto=6 action="accept|deny|close" policyid= policytype="policy" service="HTTPS"
dstcountry= srccountry= trandisp="snat" transip= transport= app= appcat= duration= sentbyte= rcvdbyte=
sentpkt= rcvdpkt=
UTM virus subtype examples exist but we use type=traffic subtype=forward and type=utm subtype=ips.

## Check Point Log Exporter CEF (syslog RFC5424 wrapped)
<PRI>1 <ISO8601Z> <host> CheckPoint - - - CEF:0|Check Point|VPN-1 & FireWall-1|R81.20|Log|Log|Unknown|
act=Accept rt=<epoch_ms or Mon dd yyyy hh:mm:ss> src= dst= spt= dpt= proto=6 in= out=
cs1Label=Rule Name cs1= cs2Label=Rule UID cs2= ifdir=inbound ifname=eth1 loguid={...}
(fields separator is space; field_value sep is =)

## F5 BIG-IP ASM (key="value", syslog)
ASM:unit_hostname="...",management_ip_address="...",policy_name="...",violations="...",
support_id="<digits>",attack_type="...",request_status="Blocked|Alerted",ip_client="...",
method="GET",uri="...",date_time="YYYY-MM-DD HH:MM:SS",severity="...",sig_names="..."

## Kubernetes audit (JSON lines)
{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"RequestResponse","auditID":"<uuid>",
"stage":"ResponseComplete","requestURI":"...","verb":"create|get|...","user":{"username":"...","groups":[...]},
"sourceIPs":["..."],"userAgent":"kubectl/...","objectRef":{"resource":"pods","subresource":"exec",
"namespace":"...","name":"...","apiVersion":"v1"},"responseStatus":{"metadata":{},"code":200|201|403},
"requestReceivedTimestamp":"<RFC3339 micro>","stageTimestamp":"<RFC3339 micro>","annotations":{...}}

## Windows Event Log (rendered Event XML) - System.Security channel
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>...<Provider Name=
"Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4624</EventID>
<Version>..</Version><Level>0</Level><Task>..</Task><Opcode>0</Opcode><Keywords>0x80...</Keywords>
<TimeCreated SystemTime="ISO"/><EventRecordID>..</EventRecordID><Correlation/><Execution ProcessID=".."
ThreadID=".."/><Channel>Security</Channel><Computer>..</Computer><Security/></System>
<EventData><Data Name="...">..</Data>...</EventData></Event>

## Sysmon XML (Microsoft-Windows-Sysmon/Operational)
Same envelope; Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
EID 1 ProcessCreate, 3 NetworkConnect, 7 ImageLoad, 8 CreateRemoteThread, 10 ProcessAccess,
11 FileCreate, 13 RegistryValueSet, 22 DnsQuery. EventData Data Name fields per EID.

## PowerShell (Microsoft-Windows-PowerShell/Operational) 4103 module logging, 4104 ScriptBlock
## WMI-Activity (Microsoft-Windows-WMI-Activity/Operational) 5857-5861

## Linux
auth.log RFC3164: "<Mon> <dd> <HH:MM:SS> <host> sshd[pid]: Failed password for <user> from <ip> port <p> ssh2"
syslog RFC5424: "<PRI>1 <ISO8601> <host> <app> <pid> <msgid> - <msg>"
auditd: "type=SYSCALL msg=audit(epoch:id): arch=c000003e syscall=59 ... exe=\"/usr/bin/...\" key=\"...\""
         "type=EXECVE msg=audit(epoch:id): argc=.. a0=\"..\" a1=\"..\""

## DNS
BIND query log: "<dd-Mon-YYYY HH:MM:SS.mmm> queries: info: client @0x.. <ip>#<port> (<qname>): query: <qname> IN A + (<server>)"
Windows DNS debug: date time PID PACKET ... UDP Rcv <ip> xxxx Q [....] A (n)name

## Web proxy (Squid access.log)
"<epoch.msec> <elapsed> <client_ip> <result_code>/<status> <bytes> <method> <url> <user> <hier>/<server> <content_type>"
