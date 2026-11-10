# Phishalyze — Phishing Email Analyzer

A command-line tool that takes a raw email (`.eml`) and reports whether it looks
like phishing, the same first-pass triage a SOC analyst does by hand. It parses
the message, runs a set of independent heuristic checks, and combines them into
a single risk score and verdict.

**Detection is self-contained.** Every verdict is produced with zero external
API calls — the logic (email-authentication analysis, lookalike-domain
detection, link and attachment inspection, body-language scoring) is all in this
repo. An optional VirusTotal layer can add known-bad reputation data on top, but
the tool never depends on it to reach a verdict.

> ⚠️ **For defensive and educational use.** This tool only *analyzes* emails you
> already have. It does not send mail, harvest credentials, or contact any live
> target. Use it on your own messages or samples you are authorised to inspect.

---

## Example

```
$ python -m phishalyze samples/phishing_paypal.eml
```

```
  From:    PayPal Service <support@paypa1.com>
  Subject: Urgent: Your account will be suspended within 24 hours
  Links:   1   Attachments: 0

  VERDICT: Phishing  —  score 100/100
  [██████████████████████████████]

  Findings (14):
  [HIGH  ] SPF fail  (+25)
  [HIGH  ] DMARC fail  (+25)
  [HIGH  ] Homoglyph lookalike of "paypal"  (+24)
           "paypa1" becomes "paypal" once look-alike characters are normalised.
  [HIGH  ] Link points to a raw IP address  (+20)
  [MEDIUM] Requests credentials or account action  (+18)
  [MEDIUM] Display name says "paypal", domain does not  (+16)
  ...
```

Run it against the clean sample (`samples/legit_newsletter.eml`) and it scores
**0/100 — Likely legitimate**.

---

## How it works

```
   message.eml
        │
        ▼
   ┌─────────┐   headers   ─▶ SPF / DKIM / DMARC results, Received chain,
   │  parse  │                 Return-Path vs From alignment, Reply-To steering
   └────┬────┘   sender    ─▶ display-name spoofing, homoglyph & typosquat
        │                      lookalike domains, brand-in-subdomain
        │         urls      ─▶ link-text vs real-href mismatch, raw-IP hosts,
        ▼                      shorteners, @-masking, high-abuse TLDs
   ┌─────────┐   attach    ─▶ dangerous extensions, double extensions,
   │  checks  │─────────────   macro-capable docs, RTL-override filenames
   └────┬────┘   body      ─▶ urgency, credential requests, lures,
        │                      generic greetings
        ▼
   ┌─────────┐        (optional) VirusTotal enrichment layered on top
   │ scoring  │
   └────┬────┘
        ▼
   risk score 0–100  +  verdict band  +  itemised findings
```

Each check returns a list of **findings**, each carrying a severity and a
weight. The score is the sum of the weights, capped at 100, mapped to a band:

| Score | Verdict |
|------:|---------|
| 70–100 | Phishing |
| 40–69  | Suspicious |
| 15–39  | Questionable |
| 0–14   | Likely legitimate |

The weights are tuned so a single strong signal (failed SPF, executable
attachment, lookalike domain) lands in *Suspicious* on its own, and two push
into *Phishing*. Because it's a transparent heuristic, you can read any verdict
straight off the findings list — there's no black box.

### What's genuinely detected here vs. looked up

The interesting engineering is self-contained:

- **Email authentication** — interprets the SPF / DKIM / DMARC results recorded
  by the receiving server, and independently checks envelope-sender alignment
  (Return-Path and Reply-To vs From), which is the idea DMARC is built on.
- **Lookalike domains** — homoglyph folding (`paypa1` → `paypal`,
  Cyrillic → Latin) plus Levenshtein distance against a watchlist of commonly
  impersonated brands. No external service.
- **Link deception** — compares where a link *claims* to go against where it
  actually points; flags raw-IP hosts, `@`-masking, shorteners.

The only thing that is an outside lookup is the **optional** VirusTotal check
(`enrichment.py`), which answers "is this specific URL/hash already known-bad".
It is off by default and isolated from the core logic on purpose.

---

## Usage

```bash
# Single file
python -m phishalyze suspicious.eml

# Several files / globs
python -m phishalyze samples/*.eml

# Machine-readable output
python -m phishalyze suspicious.eml --json

# Use in a pipeline: exit non-zero if anything is Suspicious or worse
python -m phishalyze inbox/*.eml --fail-on suspicious

# Opt in to VirusTotal reputation lookups (needs a free API key)
export VT_API_KEY=your_key_here
python -m phishalyze suspicious.eml --virustotal
```

As a library:

```python
from phishalyze import analyze_file

parsed, verdict = analyze_file("suspicious.eml")
print(verdict.label, verdict.score)
for f in verdict.findings:
    print(f.severity.label, f.title)
```

---

## Install

No dependencies for core use — it's standard-library Python (3.9+).

```bash
git clone https://github.com/AdamNazman/phishing-email-analyzer.git
cd phishing-email-analyzer
python -m phishalyze samples/phishing_paypal.eml
```

The optional VirusTotal layer needs `requests`:

```bash
pip install -r requirements.txt
```

---

## Getting test emails

- The two samples in `samples/` run out of the box.
- To test on real mail, save any message as `.eml` (in most clients: *File →
  Save As*, or drag the message to your desktop).
- Public phishing corpora exist for research if you want volume — just handle
  them in a safe environment and never open attachments outside a VM.

---

## Project layout

```
phishalyze/
├── parser.py           # .eml -> structured ParsedEmail
├── findings.py         # Finding / Severity types shared by all checks
├── checks/
│   ├── headers.py      # SPF/DKIM/DMARC, Received, Return-Path/Reply-To
│   ├── sender.py       # display-name spoof, homoglyph/typosquat domains
│   ├── urls.py         # link deception, IP hosts, shorteners, TLDs
│   ├── attachments.py  # dangerous / double / macro-capable files
│   └── body.py         # urgency, credential, lure, greeting language
├── scoring.py          # weights findings -> score + verdict band
├── enrichment.py       # OPTIONAL VirusTotal lookups (off by default)
├── report.py           # terminal + JSON output
└── cli.py              # argument parsing / entry point
samples/                # one phishing, one legit, both ready to run
tests/                  # pytest-compatible, also runnable directly
```

---

## Limitations

- Heuristic, not a classifier: unusual-but-legitimate mail can score as
  *Questionable*, and a carefully crafted phish can score low. It's a triage
  aid, not a verdict machine.
- It reads authentication results the receiving server already recorded rather
  than re-verifying DKIM signatures cryptographically. Verifying signatures with
  `dkimpy` is a natural next step.
- The brand watchlist and keyword lists are a starting set, meant to be extended.

## Possible extensions

- Cryptographic DKIM verification (`dkimpy`)
- A small Flask web UI for drag-and-drop analysis
- Public-suffix list for exact registered-domain parsing
- IOC export (STIX / CSV) for the links, domains and hashes found

## License

MIT — see [LICENSE](LICENSE).
