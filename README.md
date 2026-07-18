# paramhunt

Discover a page's parameters — and the hidden attack surface behind them — in
one command, no dependencies.

`paramhunt` fetches a URL and extracts every parameter name it can find:

- **query-string params** from links (`<a href="...?id=1">`)
- **form fields** — `input` / `select` / `textarea` names, plus each form's
  action and method
- **params referenced in JavaScript** — same-origin scripts are fetched and
  mined for `?foo=`, `fetch("...?bar=")`, `searchParams.get("qux")`,
  `new URLSearchParams(...)`, and string-concatenated query building

The output is a de-duplicated inventory of parameter names — the exact list you
feed into a fuzzer to probe for injection, IDOR, mass assignment, and hidden
debug flags like `debug=1` or `admin=true`.

## Demo

<!-- Record a run showing params pulled from links + forms + JS, then drop the
     file here. Replace this line with:  ![paramhunt demo](demo.gif) -->

_Demo GIF coming soon._

## Why

Half the parameters worth attacking are never visible in the URL bar — they're
buried in a form, or constructed inside a bundled JS file. paramhunt reads all
three sources at once and hands you a wordlist, so you spend your time testing
params instead of hunting for them.

## Install

```bash
git clone https://github.com/<you>/paramhunt
cd paramhunt
```

No pip install — Python 3 standard library only.

## Usage

```bash
python3 paramhunt.py https://example.com
python3 paramhunt.py https://example.com --no-js      # skip external JS fetching
python3 paramhunt.py https://example.com --names      # bare name list, one per line
python3 paramhunt.py https://example.com --json       # machine-readable
python3 paramhunt.py https://example.com -k           # ignore TLS cert errors
```

## Example

```
== paramhunt: https://news.ycombinator.com ==
scanned 1 script(s), found 11 unique params

from links (5):
  goto, how, id, p, site

from forms (1):
  q

from javascript (10):
  auth, goto, how, id, js, n, next, p, site, un

forms (1):
  [GET] https://hn.algolia.com/
      q
```

## Pipe it into a fuzzer

`--names` prints one param per line — a ready-made wordlist:

```bash
python3 paramhunt.py https://target.com --names > params.txt

# then fuzz each discovered param for reflected values / errors
ffuf -u "https://target.com/page?FUZZ=test" -w params.txt -mc all -fs 0
```

## How it works

1. Fetch the page, parse it with Python's `html.parser`
2. Collect link query params, form fields, and inline-JS params
3. Fetch same-origin `<script src>` files (capped) and mine them for param names
4. Merge, de-duplicate, and filter out obvious noise (`utm_*`, literals, digits)

## Notes

- Only test sites you're authorized to assess.
- External JS fetching is limited to same-origin scripts and capped at 15 files
  to stay polite; use `--no-js` for a fast HTML-only pass.

## License

MIT
