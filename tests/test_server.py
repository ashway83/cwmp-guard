import json
import logging
import os
import socket

from mitmproxy import http, ctx

config_file = os.environ.get("RESPONSES_CONFIG_FILE", "responses.json")


def load_responses():
    try:
        with open(config_file, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Responses configuration file '{config_file}' not found.")
        return {}
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in responses configuration file '{config_file}'.")
        return {}


responses = load_responses()


def get_ip_addresses():
    ip_addresses = set()
    try:
        # Get all IPv4 addresses for all network interfaces
        for interface in socket.getaddrinfo(socket.gethostname(), None):
            if interface[0] == socket.AF_INET:  # IPv4
                ip_addresses.add(interface[4][0])

    except socket.gaierror:
        pass  # Ignore errors in getting IP addresses

    return ip_addresses


def display_urls():
    port = ctx.options.listen_port if ctx.options.listen_port else 8080
    ip_addresses = get_ip_addresses()

    logging.info("URLs:")
    for ip in ip_addresses:
        url = f"http://{ip}:{port}"
        logging.info(f"  {url}")


# Call this function when the script starts
display_urls()


def request(flow: http.HTTPFlow) -> None:
    # Retrieve the header value
    header_value = flow.request.headers.get("X-Test-Payload-Id", "empty")

    if header_value in responses:
        response_config = responses[header_value]
        content_file_path = response_config.get("content", None)
        status_code = response_config["status_code"]
        content_type = response_config.get("content_type", "application/json")
        headers = response_config.get("headers", {})

        if content_file_path and os.path.exists(content_file_path):
            with open(content_file_path, "r", encoding="utf-8") as content_file:
                content = content_file.read()
        else:
            content = ""

        if status_code == 204:
            flow.response = http.Response.make(status_code=status_code, headers=headers)
        else:
            # If status code is not 204, include content and Content-Type header
            headers["Content-Type"] = content_type
            flow.response = http.Response.make(
                status_code=status_code,
                content=content.encode("utf-8"),
                headers=headers,
            )
        return

    # If no matching response is found
    flow.response = http.Response.make(
        status_code=404,
        content=b"No preconfigured response found",
        headers={"Content-Type": "text/plain"},
    )
