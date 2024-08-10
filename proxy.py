import datetime
import json
import logging
import os
import signal
import socket
import sys
from urllib.parse import urljoin, urlparse
from xml.etree.ElementTree import Element, ParseError, SubElement, fromstring, register_namespace, tostring

import colorama
from mitmproxy import ctx, http

from utils.text_styles import style_error, style_highlight, style_warning

# Define constants
INITIAL_ACS_URL = os.environ.get('ACS_URL', "https://acssec.fnet.gb.vodafone.es:6061/cwmpWeb/CPEMgt")
OVERRIDE_PARAMS_FILE = os.environ.get('OVERRIDE_PARAMS_FILE', "tr069_overrides.json")

# Initialize colorama
colorama.init()


def signal_handler(sig, frame):
    logging.debug("Signal: %s, Frame: %s" % (sig, frame))
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
                # skip loopback address
                if interface[4][0] == '127.0.0.1':
                    continue

                ip_addresses.add(interface[4][0])

    except socket.gaierror:
        pass  # Ignore errors in getting IP addresses

    return ip_addresses


class RewriteRules:
    def __init__(self):
        self.port = None
        self.url_mappings = {}
        self.key_counter = 0
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
        if hasattr(ctx.options, 'web_port'):
            # Set the port for the web interface to port + 1 if it hasn't been explicitly set
            if ctx.options.web_port == 8081:
                ctx.options.web_port = self.port + 1

    def running(self):
        self.ensure_data_folder_exists()
        self.initialize_mappings()

        acs_url_message = style_highlight("New ACS URLs:")
        hint_message = style_warning("Note: You must set the ACS URL on your router to one of the URLs below.")

        if len(self.url_mappings) == 1:
            acs_url_message = style_highlight("New ACS URL:")
            hint_message = style_warning("Note: You must set the ACS URL on your router to the URL below.")

        logging.info(f"Original ACS URL: {INITIAL_ACS_URL}")
        logging.info(hint_message)
        logging.info(acs_url_message)
        for key, mapping in self.url_mappings.items():
            logging.info(f"  {mapping['new']}")

    def request(self, flow: http.HTTPFlow) -> None:
        # Process only live flows
        if not flow.live:
            return

        request = flow.request
        # Store the original request URL value (copy) before it is modified
        original_request_url = request.url
        # Store the original request URL in flow.metadata before any URL rewriting occurs
        # This allows us to access the pre-rewrite URL later in the response handling phase
        flow.metadata['request_url'] = request.url
        if not any(request.url == mapping['new'] for mapping in self.url_mappings.values()):
            error_message = f"Error: Unrecognized URL {request.url}"
            logging.error(style_error(error_message))

            # Return a 400 response with the error message
            flow.response = http.Response.make(
                status_code=400,
                headers={"Content-Type": "text/plain"},
                content=error_message.encode('utf-8')
            )
            return

        # Rewrite request URL
        for key, url_mapping in self.url_mappings.items():
            if request.url == url_mapping['new']:
                request.url = url_mapping['original']
                logging.info(f"Rewritten request URL: {url_mapping['new']} -> {url_mapping['original']}")
                break

        # Handle GetParameterValuesResponse
        if (request.method == "POST" and request.content
                and request.headers.get("Content-Type", "").startswith("text/xml")):
            try:
                content = request.content.decode('utf-8')
                root = fromstring(content)

                # Construct override entry for InternetGatewayDevice.ManagementServer.URL
                acs_url_overrides = {}
                for key, mapping in self.url_mappings.items():
                    if original_request_url == mapping['new']:
                        acs_url_overrides = {
                            'InternetGatewayDevice.ManagementServer.URL': {
                                'value': mapping['original'],
                                'type': 'string',
                            }
                        }
                        break
                overrides = {**self.override_params['client'], **acs_url_overrides}

                inform = self.find_element(root, ".//cwmp:Inform")
                if inform is not None:
                    # Override parameters
                    self.override_parameters(root, request, overrides)
                    # Extract and save parameters
                    self.extract_and_save_parameters(root, "Inform")

                get_parameter_values_response = self.find_element(root, ".//cwmp:GetParameterValuesResponse")
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
        if (response and response.status_code == 200 and response.content
                and response.headers.get("Content-Type", "").startswith("text/xml")):
            try:
                content = flow.response.content.decode('utf-8')
                root = fromstring(content)

                # Guard statement to handle only SetParameterValues responses
                set_parameter_values = self.find_element(root, ".//cwmp:SetParameterValues")
                if set_parameter_values is None:
                    return

                # Handle InternetGatewayDevice.ManagementServer.URL
                self.handle_management_server_url(root, flow)

                # Override parameters
                self.override_parameters(root, response, self.override_params['acs'])

                # Extract and save parameters
                self.extract_and_save_parameters(root, "SetParameterValues")

            except ParseError:
                logging.error(style_error("Failed to parse XML in response."))
                logging.debug(f"Response content: {response.content.decode('utf-8')}")

    def ensure_data_folder_exists(self):
        if not os.path.exists(self.data_folder):
            os.makedirs(self.data_folder)
            logging.info(f"Created data folder: {self.data_folder}")

    def initialize_mappings(self):
        original_acs_url = INITIAL_ACS_URL
        parsed_original_acs_url = urlparse(original_acs_url)

        # Generate mappings for all possible IPv4 addresses
        for ip in get_ip_addresses():
            key = self.generate_key()
            # noinspection HttpUrlsUsage
            base_url = f"http://{ip}:{self.port}"
            acs_url = urljoin(base_url, f"{key}{parsed_original_acs_url.path}")
            self.url_mappings[key] = {'original': original_acs_url, 'new': acs_url}
            logging.info(f"Added mapping for {ip}:{self.port}: {original_acs_url} -> {acs_url}")

    def generate_key(self):
        self.key_counter += 1
        return str(self.key_counter)

    def find_element(self, root_element, xpath):
        return root_element.find(xpath, self.namespaces)

    def handle_management_server_url(self, root, flow):
        xpath = (".//cwmp:SetParameterValues/ParameterList/ParameterValueStruct["
                 "Name='InternetGatewayDevice.ManagementServer.URL']/Value")
        value_element = self.find_element(root, xpath)

        if value_element is not None and value_element.text:
            original_url = value_element.text

            # Check if this URL is already in the mapping
            existing_key = next((k for k, v in self.url_mappings.items() if v['original'] == original_url),
                                None)

            if existing_key is None:
                # If not in mapping, add to the mapping
                new_key = self.generate_key()
                parsed_url = urlparse(flow.metadata['request_url'])
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                new_url = urljoin(base_url, f"{new_key}{urlparse(original_url).path}")
                self.url_mappings[new_key] = {'original': original_url, 'new': new_url}
                logging.info(f"Added new mapping: {original_url} -> {new_url}")
            else:
                new_url = self.url_mappings[existing_key]['new']

            value_element.text = new_url
            logging.info(f"Rewritten response XML: {original_url} -> {new_url}")

            # Update the response content
            flow.response.content = tostring(root, encoding='unicode').encode('utf-8')

    def override_parameters(self, root, has_content, override_params):
        param_list_element = self.find_element(root, ".//ParameterList")

        parameters_modified = False

        for param_name, param_info in override_params.items():
            param_value = param_info['value']
            param_type = param_info['type']
            param_xpath = f".//ParameterList/ParameterValueStruct[Name='{param_name}']/Value"
            param_element = self.find_element(root, param_xpath)

            if param_element is not None:
                # If parameter exists, update its value
                if param_element.text != param_value:
                    param_element.text = param_value
                    param_element.set('{http://www.w3.org/2001/XMLSchema-instance}type', f'xsd:{param_type}')
                    logging.info(f"Updated existing parameter: {param_name} = {param_value} ({param_type})")
                    parameters_modified = True
            else:
                # If parameter doesn't exist, check if it should be added
                should_add = param_info.get('add', False)
                if should_add:
                    new_param = Element('ParameterValueStruct')
                    name_element = SubElement(new_param, 'Name')
                    name_element.text = param_name
                    value_elem = SubElement(new_param, 'Value')
                    value_elem.text = param_value
                    value_elem.set('{http://www.w3.org/2001/XMLSchema-instance}type', f'xsd:{param_type}')

                    param_list_element.append(new_param)
                    logging.info(f"Added new parameter: {param_name} = {param_value} ({param_type})")
                    parameters_modified = True
                else:
                    logging.debug(f"Parameter {param_name} not found and not set to be added. Skipping.")

        if parameters_modified:
            # Update the response content if parameters were modified
            has_content.content = tostring(root, encoding='unicode').encode('utf-8')
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
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = f"{request_name}_{timestamp}.txt"
        filepath = os.path.join(self.data_folder, filename)

        with open(filepath, 'w') as f:
            for name, value in parameters:
                f.write(f"{name}: {value}\n")

        logging.info(f"Parameters saved to {filepath}")

    @staticmethod
    def get_namespaces():
        return {
            'soap': 'http://schemas.xmlsoap.org/soap/encoding/',
            'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/',
            'cwmp': 'urn:dslforum-org:cwmp-1-0'
        }

    @staticmethod
    def register_namespaces(namespaces):
        for prefix, uri in namespaces.items():
            register_namespace(prefix, uri)

    @staticmethod
    def read_override_params():
        filename = OVERRIDE_PARAMS_FILE
        try:
            with open(filename, 'r') as override_params_file:
                params = json.load(override_params_file)
                if not isinstance(params, dict) or 'client' not in params or 'acs' not in params:
                    raise ValueError("JSON file must contain 'acs' and 'client' objects")
                return params
        except FileNotFoundError:
            logging.warning(style_warning(f"Note: {filename} not found. No parameter overrides will be applied."))
            return {'client': {}, 'acs': {}}
        except (json.JSONDecodeError, ValueError) as e:
            logging.error(style_error(f"Error parsing {filename}: {str(e)}. Please check the file format."))
            return {'client': {}, 'acs': {}}


addons = [RewriteRules()]
