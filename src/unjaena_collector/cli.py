import argparse
import sys

from .client import ServiceClient
from .runner import ProfileRunner


def main() -> int:
    parser = argparse.ArgumentParser(prog="unjaena-collector")
    parser.add_argument("--server", required=True)
    parser.add_argument("--token", required=True)
    args = parser.parse_args()

    client = ServiceClient(args.server)
    session = client.authenticate(args.token)
    profile = client.get_profile(session)
    result = ProfileRunner(client, session, profile).run()
    print(f"scanned={result['scanned']} uploaded={result['uploaded']} skipped={result['skipped']} failed={result['failed']}")
    return 0 if result["failed"] == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
