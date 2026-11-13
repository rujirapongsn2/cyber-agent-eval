# -*- coding: utf-8 -*-
"""Timezone-aware time handling and per-source native rendering.

Every event has ONE canonical instant: a tz-aware UTC datetime. Each log source
renders that instant in its real native convention. The whole org (hosts and
network devices) runs in Asia/Bangkok (ICT, UTC+07, no DST), declared in
answers/tz_conventions.json and the README.

Rendering conventions (verified against vendor behaviour):
  Windows Event XML TimeCreated SystemTime : UTC, ISO8601 'Z'
  Sysmon UtcTime field                     : UTC, 'YYYY-MM-DD HH:MM:SS.mmm'
  Linux auth.log / syslog (RFC3164)        : host LOCAL time, no offset
  Linux syslog (RFC5424)                   : LOCAL time with numeric offset
  auditd msg=audit(epoch:id)               : UTC epoch seconds
  PAN-OS Receive/Generated Time + hdr      : device LOCAL time, no offset
  FortiGate date=/time=                    : device LOCAL; tz="+0700";
                                             eventtime = UTC epoch nanoseconds
  Check Point CEF rt=                       : UTC epoch milliseconds;
                                             syslog header ISO8601 with offset
  F5 ASM date_time= + syslog header         : device LOCAL time
  BIND query log                            : server LOCAL time, ms
  Windows DNS debug log                     : server LOCAL time (M/D/YYYY h:mm:ss)
  Squid access.log                          : UTC epoch seconds.milliseconds
  Docker JSON 'time'                        : UTC, RFC3339 nanoseconds 'Z'
  Kubernetes audit timestamps               : UTC, RFC3339 microseconds 'Z'
"""
import datetime

UTC = datetime.timezone.utc
ORG_OFFSET_HOURS = 7
ORG_TZ = datetime.timezone(datetime.timedelta(hours=ORG_OFFSET_HOURS), "ICT")
ORG_TZ_NAME = "Asia/Bangkok"
ORG_OFFSET_STR = "+0700"

_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
           "Oct", "Nov", "Dec"]


def as_utc(dt):
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def local(dt):
    return as_utc(dt).astimezone(ORG_TZ)


# ---- Windows ----
def win_systemtime(dt):
    d = as_utc(dt)
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond:06d}0Z"  # 7 frac digits


def sysmon_utctime(dt):
    return as_utc(dt).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


# ---- Linux ----
def rfc3164(dt):
    d = local(dt)
    return f"{_MONTHS[d.month-1]} {d.day:2d} {d.strftime('%H:%M:%S')}"


def rfc5424_ts(dt):
    d = local(dt)
    return d.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + ORG_OFFSET_STR[:3] + ":" + ORG_OFFSET_STR[3:]


def epoch_s(dt):
    return as_utc(dt).timestamp()


def auditd_stamp(dt):
    return f"{epoch_s(dt):.3f}"


# ---- network devices ----
def pan_time(dt):
    return local(dt).strftime("%Y/%m/%d %H:%M:%S")


def pan_syslog_hdr(dt):
    d = local(dt)
    return f"{_MONTHS[d.month-1]} {d.day:2d} {d.strftime('%H:%M:%S')}"


def fgt_date(dt):
    return local(dt).strftime("%Y-%m-%d")


def fgt_time(dt):
    return local(dt).strftime("%H:%M:%S")


_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=UTC)


def fgt_eventtime_ns(dt):
    delta = as_utc(dt) - _EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000


def cef_rt_ms(dt):
    return int(round(as_utc(dt).timestamp() * 1000))


def cef_syslog_hdr(dt):
    return local(dt).strftime("%Y-%m-%dT%H:%M:%S") + ORG_OFFSET_STR[:3] + ":" + ORG_OFFSET_STR[3:]


def f5_datetime(dt):
    return local(dt).strftime("%Y-%m-%d %H:%M:%S")


def bind_time(dt):
    d = local(dt)
    return d.strftime("%d-%b-%Y %H:%M:%S.") + f"{d.microsecond // 1000:03d}"


def windns_time(dt):
    d = local(dt)
    hr = d.hour % 12 or 12
    ampm = "AM" if d.hour < 12 else "PM"
    return f"{d.month}/{d.day}/{d.year} {hr}:{d.strftime('%M:%S')} {ampm}"


def squid_epoch(dt):
    return f"{as_utc(dt).timestamp():.3f}"


def docker_time(dt):
    d = as_utc(dt)
    return d.strftime("%Y-%m-%dT%H:%M:%S.%f") + "000Z"


def k8s_time(dt):
    return as_utc(dt).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


# Machine-readable per-source timezone conventions (written to tz_conventions.json)
TZ_CONVENTIONS = {
    "_note": ("Every event has one canonical UTC instant, rendered per source in "
              "its native convention. Whole org runs Asia/Bangkok (ICT, UTC+07, "
              "no DST)."),
    "org_timezone": "Asia/Bangkok",
    "org_utc_offset": "+07:00",
    "dst": False,
    "sources": {
        "windows_event_xml": "UTC, ISO8601 with 'Z' (TimeCreated SystemTime)",
        "sysmon_utctime_field": "UTC, 'YYYY-MM-DD HH:MM:SS.mmm'",
        "linux_syslog_rfc3164": "host LOCAL time (ICT), no offset shown",
        "linux_syslog_rfc5424": "LOCAL time with numeric offset +07:00",
        "auditd": "UTC epoch seconds (msg=audit(epoch:id))",
        "panos": "device LOCAL time (ICT), no offset in field or header",
        "fortigate": "date=/time= device LOCAL; tz=+0700; eventtime=UTC epoch ns",
        "checkpoint_cef": "rt=UTC epoch ms; syslog header ISO8601 with +07:00",
        "f5_asm": "device LOCAL time (ICT)",
        "bind": "server LOCAL time (ICT), milliseconds",
        "windows_dns_debug": "server LOCAL time (ICT), M/D/YYYY h:mm:ss",
        "squid": "UTC epoch seconds.milliseconds",
        "docker_json": "UTC, RFC3339 nanoseconds with 'Z'",
        "kubernetes_audit": "UTC, RFC3339 microseconds with 'Z'",
    },
}
