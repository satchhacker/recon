#!/bin/bash

check_and_install() {
  if ! command -v $1 &> /dev/null; then
    echo "$1 not installed. Installing..."
    sudo apt install -y $1 &> /dev/null
  fi
}

# Check for figlet and lolcat and install them if missing
check_and_install figlet
check_and_install lolcat


figlet -f big -c "RECON" | lolcat

# Define the domain file name (replace with your actual filename)
domain_file="domain.txt"

# Check for Go and install if missing (adjust package managers for your system)
if ! command -v go &> /dev/null; then
  echo "Go not installed. Installing Golang..."
  sudo apt install golang-go-y &> /dev/null
fi

# List of tools to check and install
tools=(subfinder httpx katana gau gf Gxss dalfox)

# Check for tools and install them if missing
missing_tools=()
for tool in "${tools[@]}"; do
  if ! command -v "$tool" &> /dev/null; then
    missing_tools+=("$tool")
    # Suppress output during installation
    go install -v github.com/projectdiscovery/$tool/cmd/$tool@latest &> /dev/null;
    sudo cp go/bin/$tool /usr/bin &> /dev/null;
  fi
done

# Exit if any tools are still missing
if [[ ${#missing_tools[@]} -gt 0 ]]; then
  echo "Following tools are required but missing: "
  echo "${missing_tools[@]}"
  exit 1
fi

# Check if domain file exists
if [ ! -f "$domain_file" ]; then
  echo "Error: Domain file '$domain_file' not found!"
  exit 1
fi

echo "getting subdomains for target";
subfinder -dL "$domain_file" -all --recursive -o subdomains.txt &> /dev/null;

echo "getting live subdomain";
httpx -l subdomains.txt -o httpx.txt &> /dev/null;

# Loop through each URL (redirect loop output to /dev/null)
echo "gathering info about each live subdomain";
while IFS= read -r url; do
  echo "$url" | gau --threads 5 >> Endpoints.txt &> /dev/null;
done < "$domain_file"

echo "gathering enpoints using katana";
katana -jc < httpx.txt >> Endpoints.txt &> /dev/null;

echo "getting parameters from endpoints";
cat Endpoints.txt | gf xss >> xss.txt &> /dev/null;

echo "getting reflected parameters";
cat xss.txt | Gxss -p khXSS -o XSS_Ref.txt &> /dev/null;

echo "Finding xss bugs";
dalfox file XSS_Ref.txt -o Vulnerable_XSS.txt &> /dev/null;

# Print only your desired completion message
echo "Recon completed. Check the following files for results:"
# ... (list of files)

echo "Recon completed. Check the following files for results:"
echo "  - httpx.txt (Live subdomains)"
echo "  - Endpoints_final.txt (Crawled endpoints)"
echo "  - xss.txt (Potential XSS points)"
echo "  - XSS_Ref.txt (Reflected parameter checks)"
echo "  - Vulnerable_XSS.txt (Potential vulnerable XSS - Manual confirmation required)"