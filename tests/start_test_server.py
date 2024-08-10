#!/usr/bin/env python3

import argparse
import os
import subprocess
import sys

# Default values
DEFAULT_SCRIPT_NAME = "test_server.py"
DEFAULT_LISTEN_PORT = "8082"
DEFAULT_RESPONSES_CONFIG_FILE = "responses.json"


# noinspection DuplicatedCode
def main():
    # Custom usage message
    usage = f"""
    Usage: {sys.argv[0]} [options] [mitmproxy_args]

    Start mitmproxy with a test server script.

    Options:
      -s SCRIPT, --script SCRIPT
                            Set the Python script file (default: {DEFAULT_SCRIPT_NAME})
      -p PORT, --port PORT  Set the listen port (default: {DEFAULT_LISTEN_PORT})
      -r FILE, --responses-config FILE
                            Set the responses configuration file (default: {DEFAULT_RESPONSES_CONFIG_FILE})
      -i, --interactive     Start mitmproxy (interactive console)
      -w, --web             Start mitmweb (web interface)
      -h, --help            Show this help message and exit

    Any additional arguments will be passed to mitmdump/mitmproxy/mitmweb.
    """

    parser = argparse.ArgumentParser(description="Start mitmproxy with a test server script",
                                     usage=usage,
                                     add_help=False)
    parser.add_argument("-s", "--script", default=DEFAULT_SCRIPT_NAME,
                        help=f"Set the Python script file (default: {DEFAULT_SCRIPT_NAME})")
    parser.add_argument("-p", "--port", default=DEFAULT_LISTEN_PORT,
                        help=f"Set the listen port (default: {DEFAULT_LISTEN_PORT})")
    parser.add_argument("-r", "--responses-config", default=DEFAULT_RESPONSES_CONFIG_FILE,
                        help=f"Set the responses configuration file (default: {DEFAULT_RESPONSES_CONFIG_FILE})")
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")

    # Create a mutually exclusive group for -i and -w options
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("-i", "--interactive", action="store_true", help="Start mitmproxy (interactive console)")
    mode_group.add_argument("-w", "--web", action="store_true", help="Start mitmweb (web interface)")

    # Parse known args, leave the rest for mitmdump/mitmproxy/mitmweb
    args, unknown = parser.parse_known_args()

    # If -h or --help is used, print usage and exit
    if args.help:
        print(usage)
        sys.exit(0)

    # Set environment variables
    os.environ["RESPONSES_CONFIG_FILE"] = args.responses_config

    # Determine which mitmproxy variant to use
    if args.web:
        mitm_variant = "mitmweb"
    elif args.interactive:
        mitm_variant = "mitmproxy"
    else:
        mitm_variant = "mitmdump"

    # Print configuration
    print(f"Starting {mitm_variant} with the following configuration:")
    print(f"  Script: {args.script}")
    print(f"    Responses Config File: {args.responses_config}")
    print(f"  Listen Port: {args.port}")
    print(f"  Interactive: {'Yes' if args.interactive else 'No'}")
    print(f"  Web Interface: {'Yes' if args.web else 'No'}")

    # Construct mitmdump/mitmproxy/mitmweb command
    mitm_cmd = [
                   mitm_variant,
                   "-s", args.script,
                   "-p", args.port
               ] + unknown

    # Start mitmdump/mitmproxy/mitmweb
    try:
        subprocess.run(mitm_cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error starting {mitm_variant}: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: {mitm_variant} not found. Please ensure it's installed and in your PATH.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
