# GitHub Repository Reconnaissance Tool

A security tool for scanning Git repositories to find secrets, deleted files, and sensitive information.

## Features

- Scan for secrets using 25+ regex patterns (API keys, tokens, credentials)
- Find deleted files in git history
- Detect sensitive file extensions
- Analyze git history and configuration
- Generate detailed reports

## Installation

```bash
git clone https://github.com/Raunaksplanet/GitHub-Repository-Reconnaissance-Tool.git
cd github-recon-tool
```

## Usage

### Basic Scan
```bash
python3 github_recon.py
```

### Scan Specific Repository
```bash
python3 github_recon.py -p /path/to/repository
```

### Scan Options
```bash
# Only search for secrets
python3 github_recon.py --secrets-only

# Only find deleted files
python3 github_recon.py --deleted-only

# Save results to JSON file
python3 github_recon.py -o results.json
```

## Output

The tool provides:
- Repository metadata (remote URLs, branches, commit count)
- List of deleted files from git history
- Found secrets with file locations and line numbers
- Sensitive files detected by extension
- Git history analysis

## Requirements

- Python 3.6+
- Git installed on system
- Read access to target repository

## License

MIT License
