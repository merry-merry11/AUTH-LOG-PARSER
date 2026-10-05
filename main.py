import argparse
from collections import Counter
from parser import parse_file


def build_parser():
    parser = argparse.ArgumentParser(
        description="Parse and analyze Linux authentication logs."
    )

    parser.add_argument(
        "logfile",
        help="Path to the authentication log file"
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        events, skipped = parse_file(args.logfile)

    except FileNotFoundError:
        print(f"Error: log file not found: {args.logfile}")
        return

    except PermissionError:
        print(f"Error: permission denied: {args.logfile}")
        return

    except OSError as error:
        print(f"Error reading log file: {error}")
        return

    login_events = [
        event
        for event in events
        if event["event_type"] == "ssh_authentication"
    ]

    total_attempts = len(login_events)

    successes = sum(
        event["status"] == "success"
        for event in login_events
    )

    failures = sum(
        event["status"] == "failure"
        for event in login_events
    )

    usernames = Counter(
        event["username"]
        for event in login_events
        if event["username"]
    )

    source_ips = Counter(
        event["source_ip"]
        for event in login_events
        if event["source_ip"]
    )

    print("\n=== Authentication Log Summary ===")
    print(f"Parsed events       : {len(events)}")
    print(f"Skipped lines       : {skipped}")
    print(f"Total login attempts: {total_attempts}")
    print(f"Successful logins   : {successes}")
    print(f"Failed logins       : {failures}")

    print("\nTop targeted usernames:")

    if usernames:
        for username, count in usernames.most_common(5):
            print(f"  {username}: {count}")
    else:
        print("  None")

    print("\nTop originating source IPs:")

    if source_ips:
        for ip, count in source_ips.most_common(5):
            print(f"  {ip}: {count}")
    else:
        print("  None")


if __name__ == "__main__":
    main()
