# safety/whitelist.py

WHITELIST = {
    "192.168.64.7",   # Metasploitable2
    "127.0.0.1",
    "localhost"
}



def is_whitelisted(target):
    return target in WHITELIST


def ensure_whitelisted(target):
    if not is_whitelisted(target):
        raise PermissionError(f"{target} не в whitelist. Разрешено только: {WHITELIST}")
