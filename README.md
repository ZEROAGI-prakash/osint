# OSINT Tool — Professional Open-Source Intelligence Framework

A **free-services-only** OSINT (Open Source Intelligence) tool that aggregates public information about a target using:

- 🔍 **Google / Bing dorks** — targeted search queries including government document dorks
- 🏛️ **Gov-doc dorks** — search `.gov`, `.gov.in`, `.gov.uk`, court records, public databases
- 👤 **Social media enumeration** — check 50+ platforms for a username
- 📧 **Email OSINT** — breach checks (HaveIBeenPwned API), email format validation, header analysis
- 📞 **Phone lookup** — carrier, region, line type via free APIs
- 🌐 **WHOIS / DNS** — domain registration info, DNS records, reverse DNS
- 📋 **Paste site search** — find mentions on Pastebin, Ghostbin, etc.
- 🔐 **Certificate transparency** — crt.sh subdomain enumeration
- 📊 **Reports** — export results as JSON, plain text, or styled HTML

---

## Installation

```bash
git clone https://github.com/ZEROAGI-prakash/osint.git
cd osint
pip install -r requirements.txt
pip install -e .
```

---

## Usage

```
osint --help

# Search by full name
osint person --name "John Doe" --country US

# Search by email
osint email --email john.doe@example.com

# Search by username across social platforms
osint username --username johndoe123

# Search by phone number
osint phone --phone "+15551234567"

# WHOIS + DNS on a domain
osint domain --domain example.com

# Run all modules for a person
osint person --name "Jane Smith" --email jane@example.com --username janesmith --all
```

---

## Modules

| Module | Command | Description |
|---|---|---|
| Person OSINT | `osint person` | Dork-based search, gov docs, social + paste |
| Email OSINT | `osint email` | Breach lookup, MX, header parsing |
| Username enum | `osint username` | 50+ social/platform checks |
| Phone lookup | `osint phone` | Carrier, country, line type |
| Domain / DNS | `osint domain` | WHOIS, DNS, cert transparency |

---

## Free Services Used

| Service | Purpose |
|---|---|
| Google (dorking via requests) | Gov docs, public records, social profiles |
| Bing Search | Supplementary web dork |
| crt.sh | Certificate transparency / subdomain enum |
| HaveIBeenPwned (v3 free) | Email breach lookup |
| ip-api.com | IP geolocation |
| whois (python-whois) | Domain registration |
| numverify (free tier) | Phone validation |
| GitHub API (unauthenticated) | Username + repo search |
| Reddit JSON API | User profile check |
| Gravatar | Email → avatar hash |

---

## Legal & Ethical Notice

This tool is intended for **legal, ethical use only** — security research, background checks on yourself, or investigations with explicit permission.
Unauthorized use to gather private data may violate local laws. The authors accept no liability for misuse.

---

## License

MIT