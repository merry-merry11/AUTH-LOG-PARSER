import re


SYSLOG = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)


SSH_AUTH = re.compile(
    r"^(?P<result>Accepted|Failed)\s+"
    r"(?P<method>\S+)\s+for\s+"
    r"(?:(?P<invalid>invalid)\s+user\s+)?"
    r"(?P<username>\S+)\s+"
    r"from\s+(?P<ip>\S+)\s+"
    r"port\s+(?P<port>\d+)",
    re.IGNORECASE,
)


SESSION = re.compile(
    r"pam_unix\(sshd:session\):\s+"
    r"session\s+(?P<action>opened|closed)\s+"
    r"for\s+user\s+(?P<username>\S+)",
    re.IGNORECASE,
)


SUDO = re.compile(
    r"sudo(?:\[\d+\])?:\s+"
    r"(?P<username>\S+)\s*:\s+",
    re.IGNORECASE,
)


def parse_line(line):
    line = line.rstrip("\n")

    syslog = SYSLOG.match(line)

    if not syslog:
        return None

    data = syslog.groupdict()

    pid = data["pid"]

    if pid is not None:
        pid = int(pid)

    base = {
        "timestamp": data["timestamp"],
        "source_ip": None,
        "username": None,
        "event_type": None,
        "status": "unknown",
        "pid": pid,
        "port": None,
    }

    message = data["message"]

    ssh_match = SSH_AUTH.match(message)

    if (
        ssh_match
        and data["process"].lower().startswith("sshd")
    ):
        ssh = ssh_match.groupdict()

        base.update({
            "source_ip": ssh["ip"],
            "username": ssh["username"],
            "event_type": "ssh_authentication",
            "status": (
                "success"
                if ssh["result"].lower() == "accepted"
                else "failure"
            ),
            "port": int(ssh["port"]),
        })

        return base

    session_match = SESSION.search(message)

    if session_match:
        session = session_match.groupdict()

        action = session["action"].lower()

        base.update({
            "username": session["username"],
            "event_type": (
                "session_open"
                if action == "opened"
                else "session_close"
            ),
            "status": "success",
        })

        return base

    sudo_match = SUDO.search(message)

    if (
        sudo_match
        and data["process"].lower().startswith("sudo")
    ):
        sudo = sudo_match.groupdict()

        base.update({
            "username": sudo["username"],
            "event_type": "sudo_command",
            "status": "success",
        })

        return base

    return None


def parse_file(filepath):
    events = []
    skipped = 0

    with open(
        filepath,
        "r",
        encoding="utf-8",
        errors="replace"
    ) as file:

        for line in file:
            event = parse_line(line)

            if event is None:
                skipped += 1
            else:
                events.append(event)

    return events, skipped
