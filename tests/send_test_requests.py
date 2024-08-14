#!/usr/bin/env python3

import argparse
import sys

import requests


def send_request(url, payload_id):
    headers = {"X-Test-Payload-Id": payload_id}
    response = requests.get(url, headers=headers)
    return response


def print_response(response):
    print("-" * 50)
    print(f"Status Code: {response.status_code}")
    print("Headers:")
    for key, value in response.headers.items():
        print(f"  {key}: {value}")
    print("Content:")
    print(response.text)
    print("-" * 50)


def main():
    parser = argparse.ArgumentParser(
        description="Send test requests to the mitmproxy test server.",
        epilog="If no payload ID is specified, all predefined payload IDs will be tested.",
    )
    parser.add_argument(
        "url", nargs="?", help="URL to send requests to (e.g., http://localhost:8080)"
    )
    parser.add_argument(
        "payload_id",
        nargs="?",
        default=None,
        help="specific payload ID to test. If not provided, all predefined payload IDs will be tested.",
    )
    parser.add_argument(
        "-l",
        "--list",
        action="store_true",
        help="list all predefined payload IDs and exit.",
    )
    args = parser.parse_args()

    predefined_payload_ids = ["empty", "set_new_acs", "parameters", "sample"]

    if args.list:
        print("Predefined payload IDs:")
        for pid in predefined_payload_ids:
            print(f"  - {pid}")
        return

    if not args.url:
        parser.print_help()
        sys.exit(1)

    if args.payload_id:
        # Test the specified payload ID
        print(f"Testing payload ID: {args.payload_id}")
        response = send_request(args.url, args.payload_id)
        print_response(response)
    else:
        print("No specific payload ID provided. Testing all predefined payload IDs.")
        for payload_id in predefined_payload_ids:
            print(f"Testing payload ID: {payload_id}")
            response = send_request(args.url, payload_id)
            print_response(response)


if __name__ == "__main__":
    main()
