#!/usr/bin/env python3
"""
paramhunt — discover a page's parameters and hidden attack surface.

Fetches a URL and pulls out every parameter it can find:
  * query-string params from links (<a href="...?foo=1">)
  * form fields — input / select / textarea names, plus each form's action/method
  * params referenced inside the page's same-origin JavaScript
    (?foo=, fetch("...?bar="), 'baz=' + ..., searchParams.get("qux"), etc.)

The result is a de-duplicated inventory of parameter names — the exact list you
feed into a fuzzer (ffuf, Arjun, Burp Intruder) to probe for injection, IDOR,
mass assignment, and hidden debug flags.

Usage:
    python3 paramhunt.py https://example.com
    python3 paramhunt.py https://example.com --no-js      # skip JS fetching
    python3 paramhunt.py https://example.com --names      # bare name list (for ffuf -w)
    python3 paramhunt.py https://example.com --json
    python3 paramhunt.py https://example.com -k           # ignore TLS errors

Standard library only — no pip install required.
"""

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, parse_qs


class C:
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    GREY = "\033[90m"
    BOLD = "\033[1m"
    END = "\033[0m"


def color(t, c, on=True):
    return f"{c}{t}{C.END}" if on else t


# ---- fetching ------------------------------------------------------------

def fetch(url, insecure=False, timeout=15):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "paramhunt/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            charset = resp.headers.get_content_charset() or "utf-8"
            return resp.read().decode(charset, errors="replace")
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, ssl.SSLError, TimeoutError) as e:
        return None


# ---- HTML parsing --------------------------------------------------------

class PageParser(HTMLParser):
    """Collect links, form fields, and script sources from a page."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []          # href values
        self.scripts = []        # <script src> values
        self.form_fields = set() # input/select/textarea names
        self.forms = []          # {action, method}
        self._cur_form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "form":
            self._cur_form = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "get").lower(),
                "fields": [],
            }
            self.forms.append(self._cur_form)
        elif tag in ("input", "select", "textarea"):
            name = a.get("name")
            if name:
                self.form_fields.add(name)
                if self._cur_form is not None:
                    self._cur_form["fields"].append(name)

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur_form = None


# ---- JS parameter mining -------------------------------------------------

# Patterns that reveal a parameter name inside JavaScript.
JS_PATTERNS = [
    re.compile(r"[?&]([a-zA-Z_][\w\-\.]{0,40})="),          # ?foo=  &bar=
    re.compile(r"""searchParams\.(?:get|has|getAll)\(\s*['"]([\w\-\.]+)['"]"""),
    re.compile(r"""[?&]['"]\s*\+\s*['"]?([\w\-\.]+)['"]?\s*\+?"""),
    re.compile(r"""\bnew\s+URLSearchParams[\s\S]{0,80}?['"]([\w\-\.]+)['"]"""),
]

# Tokens that show up in these regexes but are never real params.
JS_NOISE = {
    "utm_source", "utm_medium", "utm_campaign", "http", "https",
    "true", "false", "null", "undefined", "function", "return",
}


def mine_js(text):
    found = set()
    for pat in JS_PATTERNS:
        for m in pat.findall(text):
            name = m.strip()
            if name and name.lower() not in JS_NOISE and not name.isdigit():
                found.add(name)
    return found


# ---- orchestration -------------------------------------------------------

def same_origin(base, target):
    b, t = urlparse(base), urlparse(urljoin(base, target))
    return (b.scheme, b.netloc) == (t.scheme, t.netloc)


def params_from_links(base, links):
    found = set()
    for href in links:
        q = urlparse(urljoin(base, href)).query
        if q:
            found.update(parse_qs(q, keep_blank_values=True).keys())
    return found


def hunt(url, insecure=False, fetch_js=True, max_js=15):
    html = fetch(url, insecure=insecure)
    if html is None:
        sys.exit(f"error: could not fetch {url}")

    parser = PageParser()
    parser.feed(html)

    link_params = params_from_links(url, parser.links)
    form_params = set(parser.form_fields)

    # Inline JS lives in the page too.
    js_params = mine_js(html)

    fetched_scripts = []
    if fetch_js:
        seen = set()
        for src in parser.scripts:
            full = urljoin(url, src)
            if full in seen or not same_origin(url, src):
                continue
            seen.add(full)
            if len(fetched_scripts) >= max_js:
                break
            body = fetch(full, insecure=insecure)
            if body:
                fetched_scripts.append(full)
                js_params |= mine_js(body)

    all_params = link_params | form_params | js_params
    return {
        "url": url,
        "params": sorted(all_params),
        "by_source": {
            "links": sorted(link_params),
            "forms": sorted(form_params),
            "javascript": sorted(js_params),
        },
        "forms": [
            {"action": urljoin(url, f["action"]) if f["action"] else url,
             "method": f["method"], "fields": f["fields"]}
            for f in parser.forms
        ],
        "scripts_scanned": fetched_scripts,
    }


# ---- output --------------------------------------------------------------

def print_report(r, on):
    print(color(f"\n== paramhunt: {r['url']} ==", C.BOLD + C.CYAN, on))
    print(color(
        f"scanned {len(r['scripts_scanned'])} script(s), "
        f"found {len(r['params'])} unique params", C.GREY, on))

    src = r["by_source"]
    for label, key, col in [
        ("from links", "links", C.GREEN),
        ("from forms", "forms", C.GREEN),
        ("from javascript", "javascript", C.YELLOW),
    ]:
        items = src[key]
        if items:
            print(color(f"\n{label} ({len(items)}):", C.BOLD, on))
            print("  " + ", ".join(color(p, col, on) for p in items))

    if r["forms"]:
        print(color(f"\nforms ({len(r['forms'])}):", C.BOLD, on))
        for f in r["forms"]:
            fields = ", ".join(f["fields"]) or "(no named fields)"
            print(f"  [{f['method'].upper()}] {f['action']}")
            print(color(f"      {fields}", C.GREY, on))

    if not r["params"]:
        print(color("\nno parameters found.", C.GREY, on))
    print()


def main():
    ap = argparse.ArgumentParser(
        description="Discover a page's parameters and hidden attack surface."
    )
    ap.add_argument("url", help="target URL")
    ap.add_argument("-k", "--insecure", action="store_true",
                    help="skip TLS certificate verification")
    ap.add_argument("--no-js", action="store_true",
                    help="don't fetch and mine external JavaScript")
    ap.add_argument("--names", action="store_true",
                    help="print only the bare param names (one per line, for ffuf -w)")
    ap.add_argument("--json", action="store_true",
                    help="emit JSON instead of the human report")
    args = ap.parse_args()

    if "://" not in args.url:
        args.url = "https://" + args.url

    r = hunt(args.url, insecure=args.insecure, fetch_js=not args.no_js)

    if args.names:
        print("\n".join(r["params"]))
    elif args.json:
        print(json.dumps(r, indent=2))
    else:
        print_report(r, on=sys.stdout.isatty())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
