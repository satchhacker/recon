#!/bin/bash

# Function to display help message
show_help() {
  echo "Usage: $0 [-d domain_file] [-u single_url] [-h]"
  echo ""
  echo "Options:"
  echo "  -d  Provide the location of the domain file"
  echo "  -u  Specify a single URL to run the command on"
  echo "  -h, --help  Display this help message"
}

check_and_install() {
  if ! command -v $1 &> /dev/null; then
    echo "$1 not installed. Installing..."
    if [ "$1" == "go" ]; then
      sudo apt install -y golang-go &> /dev/null
    else
      sudo apt install -y $1 &> /dev/null
    fi
  fi
}

# Check for figlet and lolcat and install them if missing
check_and_install figlet
check_and_install lolcat

figlet -f big -c "RECON" | lolcat

# Initialize variables
domain_file=""
single_url=""

# Parse command-line options
while getopts "d:u:h-" opt; do
  case $opt in
    d) domain_file="$OPTARG" ;;
    u) single_url="$OPTARG" ;;
    h) show_help; exit 0 ;;
    -)
      case "$OPTARG" in
        help) show_help; exit 0 ;;
        *) echo "Usage: $0 [-d domain_file] [-u single_url] [-h]" >&2; exit 1 ;;
      esac
      ;;
    *) echo "Usage: $0 [-d domain_file] [-u single_url] [-h]" >&2
       exit 1 ;;
  esac
done

# Show help if no options are provided
if [ -z "$domain_file" ] && [ -z "$single_url" ]; then
  show_help
  exit 1
fi

# Check if Go is installed and install if missing (adjust package managers for your system)
check_and_install go

# Check if curl is installed and install if missing
check_and_install curl

# List of tools to check and install
tools=(subfinder httpx katana gau gf Gxss dalfox)

# Check for tools and install them if missing
missing_tools=()
for tool in "${tools[@]}"; do
  if ! command -v "$tool" &> /dev/null; then
    missing_tools+=("$tool")
    # Suppress output during installation
    go install -v github.com/projectdiscovery/$tool/cmd/$tool@latest &> /dev/null
    sudo cp go/bin/$tool /usr/bin &> /dev/null
  fi
done

# Exit if any tools are still missing
if [[ ${#missing_tools[@]} -gt 0 ]]; then
  echo "Following tools are required but missing: "
  echo "${missing_tools[@]}"
  exit 1
fi

# Create subdomains.txt file
> subdomains.txt

if [ -n "$domain_file" ]; then
  echo "Getting Subdomains For Target From Domain File";
  subfinder -dL "$domain_file" -all --recursive -o subdomains.txt &> /dev/null;

  # Add curl command for each domain in domain_file
  echo "Fetching subdomains from crt.sh";
  while IFS= read -r domain; do
    curl -s "https://crt.sh/?q=$domain" | grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' >> subdomains.txt
  done < "$domain_file"
fi

if [ -n "$single_url" ]; then
  echo "Getting Subdomains For Target From Single URL";
  subfinder -d "$single_url" -all --recursive -o subdomains.txt &> /dev/null;

  # Add curl command for the single URL
  echo "Fetching subdomains from crt.sh";
  curl -s "https://crt.sh/?q=$single_url" | grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' >> subdomains.txt
fi

echo "Getting Live Subdomains";
httpx -l subdomains.txt -o httpx.txt &> /dev/null;

# Loop through each URL (redirect loop output to /dev/null)
echo "Gathering Info About Each Live Subdomain";
while IFS= read -r url; do
  echo "$url" | gau --threads 5 >> Endpoints.txt &> /dev/null;
done < subdomains.txt

echo "Gathering Endpoints Using Katana";
katana -jc < httpx.txt >> Endpoints.txt &> /dev/null;

echo "Gathering jsfiles";
cat Endpoints.txt | grep ".js$"  | uniq | sort;

echo "Getting Parameters From Endpoints";
cat Endpoints.txt | gf xss >> xss.txt &> /dev/null;

echo "Getting Reflected Parameters";
cat xss.txt | Gxss -p khXSS -o XSS_Ref.txt &> /dev/null;

# Ask the user if they want to run the XSS scan
read -p "Do you want to run an XSS Scan? (y/n): " run_xss_scan

if [[ "$run_xss_scan" =~ ^([yY][eE][sS]|[yY])$ ]]; then
  echo "Finding XSS bugs";
  dalfox file XSS_Ref.txt -o Vulnerable_XSS.txt &> /dev/null;
fi

# Print only your desired completion message
echo "Recon completed. Check the following files for results:"
echo "  - httpx.txt (Live subdomains)"
echo "  - Endpoints.txt (Crawled endpoints)"
echo "  - xss.txt (Potential XSS points)"
echo "  - XSS_Ref.txt (Reflected parameter checks)"
if [[ "$run_xss_scan" =~ ^([yY][eE][sS]|[yY])$ ]]; then
  echo "  - Vulnerable_XSS.txt (Potential vulnerable XSS - Manual confirmation required)"
fi
