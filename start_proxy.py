#!/usr/bin/env python3

import argparse
import os
import subprocess
import sys

# Default values
DEFAULT_ACS_URL = "https://acssec.fnet.gb.vodafone.es:6061/cwmpWeb/CPEMgt"
DEFAULT_OVERRIDE_PARAMS_FILE = "tr069_overrides.json"
DEFAULT_SCRIPT_NAME = "proxy.py"
DEFAULT_LISTEN_PORT = "8080"


# noinspection DuplicatedCode
def main():
    # Usage message
    usage = f"""
    Usage: {sys.argv[0]} [options] [mitmproxy_args]

    Start mitmproxy with a special TR-069 rewrite script.

    Options:
      -a ACS_URL, --acs-url ACS_URL
                            Set the ACS URL (default: {DEFAULT_ACS_URL})
      -o FILE, --override-params-file FILE
                            Set the override parameters file (default: {DEFAULT_OVERRIDE_PARAMS_FILE})
      -s SCRIPT, --script SCRIPT
                            Set the Python script file (default: {DEFAULT_SCRIPT_NAME})
      -p PORT, --port PORT  Set the listen port (default: {DEFAULT_LISTEN_PORT})
      -i, --interactive     Start mitmproxy (interactive console)
      -w, --web             Start mitmweb (web interface)
      -h, --help            Show this help message and exit

    Any additional arguments will be passed to mitmdump/mitmproxy/mitmweb.
    """

    parser = argparse.ArgumentParser(description="Start mitmproxy with a special TR-069 rewrite script",
                                     usage=usage,
                                     add_help=False)
    parser.add_argument("-a", "--acs-url", default=os.environ.get("ACS_URL", DEFAULT_ACS_URL),
                        help=f"Set the ACS URL (default: {DEFAULT_ACS_URL})")
    parser.add_argument("-o", "--override-params-file",
                        default=os.environ.get("OVERRIDE_PARAMS_FILE", DEFAULT_OVERRIDE_PARAMS_FILE),
                        help=f"Set the override parameters file (default: {DEFAULT_OVERRIDE_PARAMS_FILE})")
    parser.add_argument("-s", "--script", default=DEFAULT_SCRIPT_NAME,
                        help=f"Set the Python script file (default: {DEFAULT_SCRIPT_NAME})")
    parser.add_argument("-p", "--port", default=DEFAULT_LISTEN_PORT,
                        help=f"Set the listen port (default: {DEFAULT_LISTEN_PORT})")
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
    os.environ["ACS_URL"] = args.acs_url
    os.environ["OVERRIDE_PARAMS_FILE"] = args.override_params_file

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
    print(f"    ACS URL: {args.acs_url}")
    print(f"    Override Params File: {args.override_params_file}")
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
