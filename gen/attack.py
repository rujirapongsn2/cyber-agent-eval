"""MITRE ATT&CK helpers backed by the verified whitelist (schema/attack_whitelist.json).

The whitelist was generated from the official mitre-attack/attack-stix-data
enterprise-attack STIX bundle, excluding revoked/deprecated objects.
"""
import json
import os

_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WHITELIST_PATH = os.path.join(_DIR, "schema", "attack_whitelist.json")

with open(WHITELIST_PATH, encoding="utf-8") as _f:
    WHITELIST = json.load(_f)


def is_valid(tid):
    return tid in WHITELIST


def parent(tid):
    """Return parent technique id for a sub-technique, else the id itself."""
    return tid.split(".")[0]


def name(tid):
    return WHITELIST.get(tid, {}).get("name", "")


def tactics(tid):
    return WHITELIST.get(tid, {}).get("tactics", [])
