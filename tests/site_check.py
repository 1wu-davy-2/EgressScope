"""Static checks for the public intro page.

Verifies that every Chinese text node has an English translation in the
embedded dictionary, that required honest-limit copy is present, and that the
JSON-LD payload parses. Run from the project root:

    .venv/Scripts/python.exe tests/site_check.py
"""
from __future__ import annotations

import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "web" / "intro.html"

SKIP_TAGS = {"script", "style", "noscript", "textarea", "svg", "title"}
CJK = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]")
PASSED: list[str] = []
FAILED: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append(name)
        print(f"  FAIL  {name}{(' — ' + detail) if detail else ''}")


class TextCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, bool]] = []
        self.texts: list[str] = []
        self.aria: list[str] = []

    def _blocked(self) -> bool:
        return any(blocked for _, blocked in self.stack)

    def handle_starttag(self, tag: str, attrs) -> None:
        attr_map = dict(attrs)
        blocked = tag in SKIP_TAGS or "data-no-i18n" in attr_map
        self.stack.append((tag, blocked or self._blocked()))
        label = attr_map.get("aria-label")
        if label and CJK.search(label) and attr_map.get("id") not in ("lang-toggle", "theme-toggle"):
            self.aria.append(label.strip())
        if tag in ("img", "br", "hr", "input", "meta", "link"):
            self.stack.pop()

    def handle_startendtag(self, tag: str, attrs) -> None:
        attr_map = dict(attrs)
        label = attr_map.get("aria-label")
        if label and CJK.search(label):
            self.aria.append(label.strip())

    def handle_endtag(self, tag: str) -> None:
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                return

    def handle_data(self, data: str) -> None:
        if self._blocked():
            return
        text = re.sub(r"\s+", " ", data).strip()
        if text and CJK.search(text):
            self.texts.append(text)


def extract_dictionary(page: str) -> dict:
    match = re.search(r'<script type="application/json" id="i18n-en">\s*(\{.*?\})\s*</script>', page, re.S)
    assert match, "i18n-en dictionary not found"
    return json.loads(match.group(1))


def extract_jsonld(page: str) -> list[dict]:
    blocks = re.findall(r'<script type="application/ld\+json">\s*(\{.*?\})\s*</script>', page, re.S)
    return [json.loads(block) for block in blocks]


def run() -> None:
    print("\nEgressScope intro page checks")
    print("=============================")
    page = PAGE.read_text(encoding="utf-8")

    parser = TextCollector()
    parser.feed(page)
    parser.close()

    dictionary = extract_dictionary(page)
    check("i18n dictionary parses", isinstance(dictionary, dict) and len(dictionary) > 100, f"{len(dictionary)} entries")

    unique_texts = list(dict.fromkeys(parser.texts))
    missing = [text for text in unique_texts if text not in dictionary]
    check(
        "every Chinese text node is translated",
        not missing,
        f"{len(missing)} missing: {missing[:8]}",
    )

    stale = [key for key in dictionary if key not in set(unique_texts)]
    check("no stale dictionary entries", not stale, f"{len(stale)} unused: {stale[:8]}")

    values = [value for value in dictionary.values() if isinstance(value, str)]
    untranslated = [value for value in values if CJK.search(value)]
    check("no English value still contains Chinese", not untranslated, str(untranslated[:5]))

    aria_missing = [label for label in dict.fromkeys(parser.aria) if label not in page.split("const ARIA_EN")[1].split("};")[0]]
    check("aria labels are mapped for English", not aria_missing, str(aria_missing[:4]))

    for required in ("覆盖边界", "证书固定", "127.0.0.1:7890", "回环", "断网保护"):
        check(f"page keeps required copy: {required}", required in page)

    for required in ("未签名", "检测，不重定向", "仅元数据", "托盘", "未在 CI", "真实关机"):
        check(f"page states honest limit: {required}", required in page)

    for placeholder in ("__REPO_URL__",):
        check("repo placeholder still present for Pages build", placeholder in page)

    blocks = extract_jsonld(page)
    types = {entry.get("@type") for block in blocks for entry in block.get("@graph", [block])}
    check("JSON-LD parses and describes the product", {"SoftwareApplication", "FAQPage"} <= types, str(types))

    check("no external stylesheet or script", not re.search(r'<link[^>]+rel="stylesheet"[^>]+href="http', page)
          and not re.search(r'<script[^>]+src="http', page))
    check("theme toggle exists", 'id="theme-toggle"' in page)
    check("language toggle exists", 'id="lang-toggle"' in page and 'data-lang-set="en"' in page)
    check("version is current", "0.4.0" in page and "0.3.2" not in page and "0.2.0" not in page)

    print("\n=============================")
    print(f"{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        for name in FAILED:
            print("  - " + name)
        raise SystemExit(1)


if __name__ == "__main__":
    run()
