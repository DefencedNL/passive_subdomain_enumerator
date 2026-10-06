A passive subdomain enumeration tool.

## Tools Used

The script orchestrates these tools. Binary tools are optional, it uses
whatever is installed on your `PATH`, and the built-in HTTP sources need
no installation or API keys.

### Enumeration — binary tools (optional)
| Tool | Purpose |
|------|---------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain discovery |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Finds domains and subdomains |
| [amass](https://github.com/owasp-amass/amass) | Passive subdomain enumeration |
| [findomain](https://github.com/findomain/findomain) | Fast subdomain enumerator |

### Enumeration — built-in sources (no binary, no API key)
| Source | Purpose |
|--------|---------|
| [crt.sh](https://crt.sh) | Certificate Transparency logs |
| [Certspotter](https://sslmate.com/certspotter/) | Certificate Transparency logs (SSLMate) |
| [HackerTarget](https://hackertarget.com) | Passive DNS |
| [AlienVault OTX](https://otx.alienvault.com) | Passive DNS |

### Liveness probing (one required)
| Tool | Purpose |
|------|---------|
| [httprobe](https://github.com/tomnomnom/httprobe) | Checks which hosts respond over HTTP/HTTPS |
| [httpx](https://github.com/projectdiscovery/httpx) | Fast HTTP prober (alternative to httprobe) |

### Screenshotting (optional)
| Tool | Purpose |
|------|---------|
| [gowitness](https://github.com/sensepost/gowitness) | Screenshots live hosts with headless Chrome |

## Install dependencies
`sudo apt-get update -y && sudo apt-get install golang-go y && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && go install -v github.com/tomnomnom/assetfinder@latest && go install -v github.com/owasp-amass/amass/v4/...@master && go install -v github.com/tomnomnom/httprobe@latest && go install github.com/sensepost/gowitness@latest && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip && unzip -o findomain-linux.zip && chmod +x findomain && sudo mv findomain /usr/local/bin/findomain && export PATH="$PATH:$(go env GOPATH)/bin"`

## How to run
`python3 subdomain_finder.py -subdomains fqdns.txt --outfile subdomains.txt --screenshot`
