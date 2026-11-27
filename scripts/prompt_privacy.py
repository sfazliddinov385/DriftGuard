"""Prepare the healer's selected fields for the model on the local runner."""

import ipaddress
import json
import re


ACCOUNT_FIELDS = {"user", "username", "accountname", "subjectusername", "targetusername", "parentuser"}
GUID = re.compile(r"(?i)(\{)?\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b(?(1)\})")
IP_TOKEN = re.compile(r"(?i)(?<![\w.])(?:[a-f\d.]*:){2,}[a-f\d:.]*(?:%[\w.-]+)?|(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}\b")
HOME = re.compile(r"""(?i)((?:\\Users\\|/home/|/Users/))([^\\/"'\r\n]+?)(?=[\\/]|["'\r\n]|$)""")
PRINCIPAL = re.compile(r"(?i)(?<![\w\\/:.-])(?:NT AUTHORITY|[\w.-]+)\\[\w.$@-]+(?![\w\\.-])")
LABELED_ACCOUNT = re.compile(
    r"""(?i)(\b(?:user(?:name)?|accountname)\s*[=:]\s*|(?:^|\s)(?:/u|/ru|-user(?:name)?)\s+)(?:"[^"]*"|'[^']*'|[^,;\s"']+)"""
)


def account_field(key):
    return key.split("|", 1)[0].casefold() in ACCOUNT_FIELDS


def account_names(events):
    names = set()
    for event in events:
        for key, value in event.items():
            if account_field(key) and isinstance(value, str):
                name = value.strip().split("\\")[-1].split("@")[0]
                if name and name != "-":
                    names.add(name)
    return sorted(names, key=len, reverse=True)


def mask_ip(match):
    token = match.group().rstrip(".")
    try:
        ipaddress.ip_address(token)
    except ValueError:
        return match.group()
    return "[REDACTED_IP]" + match.group()[len(token):]


def mask_home(match):
    root, account = match.groups()
    if account.casefold() in {"public", "default", "shared", "all users"}:
        return match.group()
    return root + "[REDACTED_USER]"


def redact_text(text, names=()):
    text = GUID.sub(lambda m: "{REDACTED_GUID}" if m[1] else "[REDACTED_GUID]", text)
    text = IP_TOKEN.sub(mask_ip, text)
    text = re.sub(r"(?i)[\w.%+-]+@[\w.-]+\.[a-z]{2,}", "[REDACTED_EMAIL]", text)
    text = HOME.sub(mask_home, text)
    text = LABELED_ACCOUNT.sub(r"\1[REDACTED_USER]", text)
    text = PRINCIPAL.sub("[REDACTED_USER]", text)
    for name in names:
        text = re.sub(r"(?<![\w.-])" + re.escape(name) + r"(?![\w.-])", "[REDACTED_USER]", text, flags=re.I)
    return text


def clean(value, names, key=""):
    if isinstance(value, dict):
        return {redact_text(k, names): clean(v, names, k) for k, v in value.items()}
    if isinstance(value, list):
        return [clean(item, names, key) for item in value]
    if account_field(key) and value is not None:
        return "[REDACTED_USER]"
    return redact_text(value, names) if isinstance(value, str) else value


def model_messages(messages, names=()):
    """Redact native values before serialization, including messages added on retries."""
    result = []
    for message in messages:
        content = clean(message["content"], names)
        if not isinstance(content, str):
            content = json.dumps(content, ensure_ascii=False)
        result.append({"role": message["role"], "content": content})
    return result
