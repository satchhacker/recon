# Recon Tool

## Installation

1. git clone https://github.com/yourusername/recon.git
2. cd recon
3. chmod +x recon.sh
4. ln -s $(pwd)/recon.sh /usr/bin/recon
5. Make sure to have domains put in domain.txt
6. run recon tool in the same directory as domain.txt

To use the `recon` tool, simply run:

recon

## Usage

The `recon` tool is a reconnaissance script that automates the process of gathering information about a target domain. It uses several tools like Subfinder, HTTPX, Katana, GAU, GF, Gxss, and Dalfox to find subdomains, enumerate endpoints, and identify potential XSS vulnerabilities.



This will execute the script and perform the reconnaissance tasks. The results will be saved in various files (`httpx.txt`, `Endpoints.txt`, `xss.txt`, `XSS_Ref.txt`, `Vulnerable_XSS.txt`) in the same directory where the script is located.

## Disclaimer

This tool is intended for educational and research purposes only. The author is not responsible for any misuse or damage caused by this tool.

