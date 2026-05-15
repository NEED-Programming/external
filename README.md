# recon.sh

Automated recon pipeline for subdomain enumeration, DNS analysis, and SSL/TLS scanning. Point it at a domain (or a list of them) and it handles the rest — including installing any missing tools.

---

## Features

- **Subdomain enumeration** via `subfinder` (passive) and `crt.sh` (certificate transparency)
- **Live host probing** via `dnsx` — filters discovered subdomains down to DNS-verified live hosts only
- **DNS zone transfer attempts** via `dnsrecon`
- **SSL/TLS analysis** via `sslscan` + `sslyze`, run concurrently with a configurable job pool
- **Auto-installs missing tools** — detects your package manager, falls back to Go install or direct GitHub release downloads
- **Single domain or bulk file** — scan one target or a whole list in one run

---

## Requirements

- Bash 4.0+
- `curl` and `jq` (auto-installed if missing)
- One of: `apt-get`, `dnf`, `brew`, or `go` (for tool installation)
- `sudo` access recommended (for writing to `/usr/local/bin`; falls back to `~/bin`)

---

## Installation

```bash
git clone https://github.com/yourname/recon.sh
cd recon.sh
chmod +x recon.sh
```

No other setup needed. Missing tools are detected and installed automatically on first run.

---

## Usage

```bash
./recon.sh [-d <domain>] [-f <target_file>] [-o <output_dir>] [-p <parallel_jobs>]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-d` | Single target domain | — |
| `-f` | File of domains, one per line | — |
| `-o` | Output base directory | `./recon_<timestamp>` |
| `-p` | Parallel SSL scan jobs per domain | `3` |

At least one of `-d` or `-f` is required. Both can be used together — duplicates are removed automatically.

### Examples

```bash
# Single domain
./recon.sh -d example.com

# Bulk targets from file
./recon.sh -f targets.txt

# Both combined, custom output dir
./recon.sh -d example.com -f targets.txt -o ./output

# Crank up parallel SSL jobs
./recon.sh -f targets.txt -p 10
```

---

## Target File Format

One domain per line. Blank lines and `#` comments are ignored.

```
# Primary targets
example.com
sub.example.com

# Secondary targets
another.com
```

---

## Output Structure

### Single domain

```
recon_<timestamp>/
├── subdomains_subfinder.txt    # Raw subfinder output
├── subdomains_crtsh.txt        # Raw crt.sh output
├── subdomains_all.txt          # Merged & deduplicated
├── subdomains_live.txt         # DNS-verified live hosts only
├── dnsrecon_zonetransfer.txt   # Zone transfer attempt (text)
├── dnsrecon_zonetransfer.xml   # Zone transfer attempt (XML)
└── ssl/
    ├── sslscan_<host>.txt
    └── sslyze_<host>.txt
```

### Multiple domains

```
recon_<timestamp>/
├── example.com/
│   └── (same structure as above)
├── target2.com/
│   └── ...
└── target3.com/
    └── ...
```

---

## Tool Installation Fallback Chain

For each tool, the script tries each step in order and stops at the first success:

| Tool | Fallback chain |
|------|---------------|
| `subfinder` | apt/brew → `go install` → GitHub release download |
| `dnsx` | apt/brew → `go install` → GitHub release download |
| `dnsrecon` | pip3 → apt → git clone + pip install + wrapper script |
| `sslscan` | apt/brew → GitHub release download |
| `sslyze` | pip3 → pip |
| `curl` | package manager |
| `jq` | package manager → GitHub release download |

If a binary can't be written to `/usr/local/bin` (no sudo), it installs to `~/bin` and adds it to `PATH` for the current session.

---

## Notes

- Zone transfer failures are normal and expected. Almost all production targets refuse AXFR requests — the script warns and continues.
- SSL scans run against the root domain plus all live subdomains. Adjust `-p` based on your machine and network.
- crt.sh can be slow or temporarily unavailable. The script retries 3 times with 10-second delays before skipping it. `subfinder` results are always preserved.
- The `script` command is used to preserve ANSI colour output in sslscan/sslyze result files.

---

## License

MIT
