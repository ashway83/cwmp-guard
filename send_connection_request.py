#!/usr/bin/env python3

import requests
import argparse
from requests.auth import HTTPBasicAuth


def send_tr069_connection_request(url, username, password):
    try:
        response = requests.get(url, auth=HTTPBasicAuth(username, password))
        response.raise_for_status()
        print(
            f"Connection request sent successfully. Status code: {response.status_code}"
        )
    except requests.exceptions.RequestException as e:
        print(f"Error sending connection request: {e}")


def main():
    parser = argparse.ArgumentParser(description="Send TR-069 Connection Request")
    parser.add_argument("url", help="URL to send the connection request to")
    parser.add_argument("username", help="Username for Basic HTTP Authentication")
    parser.add_argument("password", help="Password for Basic HTTP Authentication")

    args = parser.parse_args()

    send_tr069_connection_request(args.url, args.username, args.password)


if __name__ == "__main__":
    main()
