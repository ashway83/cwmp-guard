import json
import logging
import os
import signal
import socket
import sys
import uuid
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urlunparse
from xml.etree.ElementTree import (
    Element,
    ParseError,
    SubElement,
    fromstring,
    indent,
    register_namespace,
    tostring,
)

import colorama
from mitmproxy import ctx, http

from utils.text_styles import style_error, style_highlight, style_warning

# Define constants
URL_MAPPINGS_FILE = os.environ.get("URL_MAPPINGS_FILE", "url_mappings.json")
OVERRIDE_PARAMS_FILE = os.environ.get("OVERRIDE_PARAMS_FILE", "tr069_overrides.json")

# Initialize colorama
colorama.init()


def signal_handler(sig, frame):
    logging.debug(f"Signal: {sig}, Frame: {frame}")
    logging.info("Termination signal received. Cleaning up...")
    colorama.deinit()
    logging.info("Cleanup complete. Exiting.")
    sys.exit(0)


# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


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


class RewriteRules:
    def __init__(self):
        self.port = None
        self.url_mappings = {}
        self.url_mappings_file = URL_MAPPINGS_FILE
        self.override_params = self.read_override_params()
        self.namespaces = self.get_namespaces()
        self.register_namespaces(self.namespaces)
        self.data_folder = "data"

    # noinspection PyUnusedLocal
    def load(self, loader):
        # Get the port mitmproxy is listening on
        # Note: There's no way to get the actual port from the context
        # ctx.options.listen_port is populated only when the port is set explicitly
        # We need to fall back to mitmproxy default 8080 if port was not specified
        self.port = ctx.options.listen_port if ctx.options.listen_port else 8080

        # Allow connections from public IP addresses
        ctx.options.block_global = False

        # Check if web interface is enabled
        if hasattr(ctx.options, "web_port"):
            # Set the port for the web interface to port + 1 if it hasn't been explicitly set
            if ctx.options.web_port == 8081:
                ctx.options.web_port = self.port + 1

    def running(self):
        self.load_url_mappings()
        self.show_local_urls()
        self.ensure_data_folder_exists()

    def request(self, flow: http.HTTPFlow) -> None:
        # Process only live flows
        if not flow.live:
            return

        request = flow.request
        # Get the mapping key from the request URL
        key = self.get_key_by_local_url(request.url)
        # Check if the request URL is one of the local URLs
        if not key:
            error_message = f"Error: Unrecognized URL {request.url}"
            logging.error(style_error(error_message))

            # Return a 400 response with the error message
            flow.response = http.Response.make(
                status_code=400,
                headers={"Content-Type": "text/plain"},
                content=error_message.encode("utf-8"),
            )
            return

        # Store the original request URL in flow.metadata before any URL rewriting occurs
        # This allows us to access the pre-rewrite URL later in the response handling phase
        original_request_url = request.url
        flow.metadata["request_url"] = request.url

        # Rewrite request URL
        new_request_url = self.get_remote_url_by_key(key)
        request.url = new_request_url
        logging.info(
            f"Rewritten request URL: {original_request_url} -> {new_request_url}"
        )

        # Handle GetParameterValuesResponse
        if (
            request.method == "POST"
            and request.content
            and request.headers.get("Content-Type", "").startswith("text/xml")
        ):
            try:
                content = request.content.decode("utf-8")
                root = fromstring(content)

                # Construct override entry for InternetGatewayDevice.ManagementServer.URL
                acs_url_overrides = {}
                for key, mapping in self.url_mappings.items():
                    if original_request_url == mapping["new"]:
                        acs_url_overrides = {
                            "InternetGatewayDevice.ManagementServer.URL": {
                                "value": mapping["original"],
                                "type": "string",
                            }
                        }
                        break
                overrides = {**self.override_params["client"], **acs_url_overrides}

                inform = self.find_element(root, ".//cwmp:Inform")
                if inform is not None:
                    # Override parameters
                    self.override_parameters(root, request, overrides)
                    # Extract and save parameters
                    self.extract_and_save_parameters(root, "Inform")

                get_parameter_values_response = self.find_element(
                    root, ".//cwmp:GetParameterValuesResponse"
                )
                if get_parameter_values_response is not None:
                    # Override parameters
                    self.override_parameters(root, request, overrides)
                    # Extract and save parameters
                    self.extract_and_save_parameters(root, "GetParameterValuesResponse")
            except ParseError:
                logging.error(style_error("Failed to parse XML in request."))
                logging.debug(f"Response content: {request.content.decode('utf-8')}")

    def response(self, flow: http.HTTPFlow) -> None:
        # Process only live flows
        if not flow.live:
            return

        response = flow.response
        if (
            response
            and response.status_code == 200
            and response.content
            and response.headers.get("Content-Type", "").startswith("text/xml")
        ):
            try:
                content = flow.response.content.decode("utf-8")
                root = fromstring(content)

                # Guard statement to handle only SetParameterValues responses
                set_parameter_values = self.find_element(
                    root, ".//cwmp:SetParameterValues"
                )
                if set_parameter_values is None:
                    return

                # Handle InternetGatewayDevice.ManagementServer.URL
                self.handle_management_server_url(root, flow)

                # Override parameters
                self.override_parameters(root, response, self.override_params["acs"])

                # Extract and save parameters
                self.extract_and_save_parameters(root, "SetParameterValues")

            except ParseError:
                logging.error(style_error("Failed to parse XML in response."))
                logging.debug(f"Response content: {response.content.decode('utf-8')}")

    def ensure_data_folder_exists(self):
        if not os.path.exists(self.data_folder):
            os.makedirs(self.data_folder)
            logging.info(f"Created data folder: {self.data_folder}")

    def load_url_mappings(self):
        try:
            with open(self.url_mappings_file, "r") as f:
                url_mappings = json.load(f)

            # Check each mapping has a 'url' attribute
            missing_url_keys = [
                key for key, value in url_mappings.items() if "url" not in value
            ]
            if missing_url_keys:
                raise ValueError(
                    f"Missing 'url' value for the following mapping keys: {', '.join(missing_url_keys)}"
                )

            # Normalize URLs
            for value in url_mappings.values():
                value["url"] = self.normalize_url(value["url"])

            self.url_mappings = url_mappings

            # Save the mappings
            self.save_url_mappings()

        except FileNotFoundError:
            logging.critical(
                style_error(
                    f"ACS URL mappings file '{self.url_mappings_file}' not found."
                )
            )
            sys.exit(1)
        except json.JSONDecodeError as e:
            logging.critical(
                style_error(
                    f"Failed to parse '{self.url_mappings_file}'. "
                    f"The file contains invalid JSON. Details: {str(e)}"
                )
            )
            sys.exit(1)
        except ValueError as ve:
            logging.critical(style_error(str(ve)))
            sys.exit(1)
        except Exception as e:
            logging.critical(
                style_error(
                    f"An unexpected error occurred while reading "
                    f"the ACS URL mappings file: {str(e)}"
                )
            )
            sys.exit(1)

        if not self.url_mappings:
            logging.critical(
                style_error(
                    "ACS URL mappings are not configured. Please check the mappings file."
                )
            )
            sys.exit(1)

    def save_url_mappings(self):
        try:
            with open(self.url_mappings_file, "w") as file:
                json.dump(self.url_mappings, file, indent=2)
            logging.debug(
                f"URL mappings successfully saved to {self.url_mappings_file}"
            )
        except IOError as e:
            logging.error(
                f"Error writing ACS URL mappings to file {self.url_mappings_file}: {e}"
            )
        except Exception as e:
            logging.error(
                f"An unexpected error occurred while saving ACS URL mappings: {e}"
            )

    def show_local_urls(self):
        if ctx.options.listen_host:
            ip_addresses = [ctx.options.listen_host]
        else:
            ip_addresses = get_ip_addresses()

        # Construct local URLs for each key
        local_urls = {}
        for key in self.url_mappings.keys():
            local_urls[key] = []
            # Construct URLs for each IP address that the proxy is listening on
            for ip in ip_addresses:
                # noinspection HttpUrlsUsage
                base_url = f"http://{ip}:{self.port}"
                acs_url = urljoin(base_url, key)
                local_urls[key].append(acs_url)

        single_url = len(local_urls) == 1 and len(next(iter(local_urls.values()))) == 1
        logging.info(
            style_warning(
                f"Note: You must set the ACS URL on your device to "
                f"{'the URL' if single_url else 'one of the URLs'} below."
            )
        )
        for key, urls in local_urls.items():
            logging.info(
                style_highlight(
                    f"{'URL' if len(urls) == 1 else 'URLs'} for {self.url_mappings[key]['url']}"
                )
            )
            for url in urls:
                logging.info(f"  {url}")

    def generate_key(self):
        while True:
            # Generate a new GUID and shorten it to 4 characters
            short_guid = str(uuid.uuid4())[:4]

            # Check if this shortened GUID already exists as a key in url_mappings
            if short_guid not in self.url_mappings.keys():
                return short_guid

    def get_key_by_local_url(self, url):
        parsed_url = urlparse(url)
        path = parsed_url.path.split("/")[1]

        # Check if the path is present in url_mappings as a key
        if path in self.url_mappings:
            return path

        # No match found
        return None

    def get_key_by_remote_url(self, url):
        for key, mapping in self.url_mappings.items():
            if mapping["url"] == url:
                return key
        return None

    def get_remote_url_by_key(self, key):
        return self.url_mappings[key]["url"]

    def find_element(self, root_element, xpath):
        return root_element.find(xpath, self.namespaces)

    def handle_management_server_url(self, root, flow):
        xpath = (
            ".//cwmp:SetParameterValues/ParameterList/ParameterValueStruct["
            "Name='InternetGatewayDevice.ManagementServer.URL']/Value"
        )
        value_element = self.find_element(root, xpath)

        local_acs_url = flow.metadata["request_url"]
        if value_element is not None and value_element.text:
            new_remote_acs_url = self.normalize_url(value_element.text)

            # Check if this URL is already in the mapping
            existing_key = self.get_key_by_remote_url(new_remote_acs_url)

            if existing_key is None:
                # If not, create a new mapping
                key = self.generate_key()
                self.url_mappings[key] = {"url": new_remote_acs_url}
                self.url_mappings[key]["added_by_acs"] = True
                self.url_mappings[key]["added_at"] = datetime.now(
                    timezone.utc
                ).isoformat()
                logging.info(f"Added new mapping: {key} -> {new_remote_acs_url}")
                self.save_url_mappings()
            else:
                key = existing_key

            # Rewrite the URL in the response
            parsed_url = urlparse(local_acs_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            new_local_acs_url = urljoin(base_url, f"{key}")

            value_element.text = new_local_acs_url
            logging.info(
                f"Rewritten response XML: {new_remote_acs_url} -> {new_local_acs_url}"
            )

            # Update the response content
            flow.response.content = tostring(root, encoding="unicode").encode("utf-8")

    def override_parameters(self, root, has_content, override_params):
        param_list_element = self.find_element(root, ".//ParameterList")

        parameters_modified = False

        for param_name, param_info in override_params.items():
            param_value = param_info["value"]
            param_type = param_info["type"]
            param_xpath = (
                f".//ParameterList/ParameterValueStruct[Name='{param_name}']/Value"
            )
            param_element = self.find_element(root, param_xpath)

            if param_element is not None:
                # If parameter exists, update its value
                if param_element.text != param_value:
                    param_element.text = param_value
                    param_element.set(
                        "{http://www.w3.org/2001/XMLSchema-instance}type",
                        f"xsd:{param_type}",
                    )
                    logging.info(
                        f"Updated existing parameter: {param_name} = {param_value} ({param_type})"
                    )
                    parameters_modified = True
            else:
                # If parameter doesn't exist, check if it should be added
                should_add = param_info.get("add", False)
                if should_add:
                    new_param = Element("ParameterValueStruct")
                    name_element = SubElement(new_param, "Name")
                    name_element.text = param_name
                    value_elem = SubElement(new_param, "Value")
                    value_elem.text = param_value
                    value_elem.set(
                        "{http://www.w3.org/2001/XMLSchema-instance}type",
                        f"xsd:{param_type}",
                    )

                    param_list_element.append(new_param)
                    logging.info(
                        f"Added new parameter: {param_name} = {param_value} ({param_type})"
                    )
                    parameters_modified = True
                else:
                    logging.debug(
                        f"Parameter {param_name} not found and not set to be added. Skipping."
                    )

        if parameters_modified:
            # Update the response content if parameters were modified
            parameter_value_struct_count = len(
                param_list_element.findall("ParameterValueStruct")
            )
            param_list_element.set(
                "{http://schemas.xmlsoap.org/soap/encoding/}arrayType",
                f"ParameterValueStruct[{parameter_value_struct_count}]",
            )
            indent(root)
            has_content.content = tostring(root, encoding="unicode").encode("utf-8")
            logging.debug("Parameters were modified. Updated content.")
        else:
            logging.debug("No parameters were modified. Content unchanged.")

    def extract_and_save_parameters(self, root, request_name):
        # Extract all parameters and values
        parameters = []
        xpath = f".//cwmp:{request_name}/ParameterList/ParameterValueStruct"
        for param in root.findall(xpath, self.namespaces):
            name = param.find("Name").text
            value = param.find("Value").text
            parameters.append((name, value))

        # Log parameters
        logging.info(f"{request_name} Parameters:")
        for name, value in parameters:
            logging.info(f"  {name}: {value}")

        # Save parameters to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = f"{request_name}_{timestamp}.txt"
        filepath = os.path.join(self.data_folder, filename)

        with open(filepath, "w") as f:
            for name, value in parameters:
                f.write(f"{name}: {value}\n")

        logging.info(f"Parameters saved to {filepath}")

    @staticmethod
    def get_namespaces():
        return {
            "soap": "http://schemas.xmlsoap.org/soap/encoding/",
            "soapenv": "http://schemas.xmlsoap.org/soap/envelope/",
            "cwmp": "urn:dslforum-org:cwmp-1-0",
        }

    @staticmethod
    def register_namespaces(namespaces):
        for prefix, uri in namespaces.items():
            register_namespace(prefix, uri)

    @staticmethod
    def read_override_params():
        filename = OVERRIDE_PARAMS_FILE
        try:
            with open(filename, "r") as override_params_file:
                params = json.load(override_params_file)
                if (
                    not isinstance(params, dict)
                    or "client" not in params
                    or "acs" not in params
                ):
                    raise ValueError(
                        "JSON file must contain 'acs' and 'client' objects"
                    )
                return params
        except FileNotFoundError:
            logging.warning(
                style_warning(
                    f"Note: {filename} not found. No parameter overrides will be applied."
                )
            )
            return {"client": {}, "acs": {}}
        except (json.JSONDecodeError, ValueError) as e:
            logging.error(
                style_error(
                    f"Error parsing {filename}: {str(e)}. Please check the file format."
                )
            )
            return {"client": {}, "acs": {}}

    @staticmethod
    def normalize_url(url):
        parsed_url = urlparse(url)

        # Remove default ports
        netloc = parsed_url.netloc.lower()
        if (parsed_url.scheme == "http" and parsed_url.netloc.endswith(":80")) or (
            parsed_url.scheme == "https" and parsed_url.netloc.endswith(":443")
        ):
            netloc = netloc.rsplit(":", 1)[0]

        # Normalize the root path
        path = parsed_url.path if parsed_url.path else "/"

        return urlunparse(
            (
                parsed_url.scheme,
                netloc,
                path,
                parsed_url.params,
                parsed_url.query,
                parsed_url.fragment,
            )
        )


addons = [RewriteRules()]
