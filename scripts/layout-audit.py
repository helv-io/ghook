#!/usr/bin/env python3
"""Visual layout audit for ghook.

Renders every public and admin page at 1440, 1024, 768 and 390. Fails on
horizontal page overflow, mid-word wrapping, a text node narrower than
about three characters, or a .gh-word that breaks across lines.

Usage:
  LAYOUT_BASE=http://127.0.0.1:8091 \\
  LAYOUT_COOKIE=/tmp/ghook-saas-demo/session.cookie \\
  LAYOUT_SHOTS=/workspace/ghook-shots/v014-audit \\
  python3 scripts/layout-audit.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = os.environ.get("LAYOUT_BASE", "http://127.0.0.1:8091").rstrip("/")
COOKIE_FILE = Path(os.environ.get("LAYOUT_COOKIE", "/tmp/ghook-saas-demo/session.cookie"))
SHOT_DIR = Path(os.environ.get("LAYOUT_SHOTS", "/workspace/ghook-shots/v014-audit"))
ACCOUNT_AFTER = Path(os.environ.get("LAYOUT_ACCOUNTS_AFTER", "/workspace/ghook-shots"))
WIDTHS = (1440, 1024, 768, 390)
PUBLIC = {"/login", "/privacy", "/terms"}
PAGES = [
    "/login",
    "/privacy",
    "/terms",
    "/admin",
    "/admin/account",
    "/admin/accounts",
    "/admin/audit",
    "/admin/settings",
    "/admin/targets",
    "/admin/targets/new",
    "/admin/targets/1",
    "/admin/targets/2",
    "/admin/routes",
    "/admin/routes/new",
    "/admin/routes/1",
    "/admin/routes/2",
    "/admin/deliveries",
    "/admin/deliveries/1",
]

JS = r"""
() => {
  const de = document.documentElement;
  const body = document.body;
  // scrollbar-gutter:stable can make scrollWidth == clientWidth even when
  // content was tight; still record a delta, but mid-word checks are the
  // real test.
  const pageDelta = Math.max(de.scrollWidth, body.scrollWidth) - de.clientWidth;

  const visible = (el) => {
    if (!el) return false;
    const cs = getComputedStyle(el);
    if (cs.display === "none" || cs.visibility === "hidden" || cs.opacity === "0") return false;
    const r = el.getBoundingClientRect();
    // Card-layout tables collapse the thead to a 1px box below 800px.
    return r.width >= 3 && r.height >= 3;
  };

  const chWidth = (el) => {
    const cs = getComputedStyle(el);
    const size = parseFloat(cs.fontSize) || 16;
    return size * 0.5;
  };

  const wordmarks = [];
  for (const el of document.querySelectorAll(".gh-word")) {
    if (!visible(el)) continue;
    const rects = [...el.getClientRects()].filter(r => r.width > 0 && r.height > 0);
    const tops = new Set(rects.map(r => Math.round(r.top)));
    const text = (el.textContent || "").replace(/\s+/g, "");
    if (tops.size > 1 || (rects.length > 1 && text.length <= 12)) {
      wordmarks.push({
        text: el.textContent,
        rects: rects.length,
        tops: [...tops],
        widths: rects.map(r => Math.round(r.width)),
      });
    }
  }

  const broken = [];
  const narrow = [];
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  while (walker.nextNode()) {
    const node = walker.currentNode;
    const parent = node.parentElement;
    if (!parent) continue;
    if (["SCRIPT", "STYLE", "NOSCRIPT", "TEXTAREA", "TITLE"].includes(parent.tagName)) continue;
    if (!visible(parent)) continue;
    const text = node.nodeValue;
    if (!text || !text.trim()) continue;
    const ch = chWidth(parent);
    let i = 0;
    while (i < text.length) {
      while (i < text.length && /\s/.test(text[i])) i++;
      if (i >= text.length) break;
      let j = i;
      while (j < text.length && !/\s/.test(text[j])) j++;
      const word = text.slice(i, j);
      // Drag handles and similar glyph stacks are not words.
      if (/^[⋮·•│|]+$/.test(word)) { i = j; continue; }
      const range = document.createRange();
      range.setStart(node, i);
      range.setEnd(node, j);
      const rects = [...range.getClientRects()].filter(r => r.width > 0 && r.height > 0);
      const tops = new Set(rects.map(r => Math.round(r.top)));
      if (word.length >= 2 && tops.size > 1) {
        // Path-like tokens may wrap at a slash. Anything else mid-word is a fail,
        // as is a fragment narrower than about two characters.
        const isPathish = /[\/]/.test(word);
        const shattered = rects.some(r => r.width < 2 * ch);
        if (!isPathish || shattered) {
          broken.push({
            word,
            tag: parent.tagName,
            cls: String(parent.className || "").slice(0, 80),
            rects: rects.length,
            widths: rects.map(r => +r.width.toFixed(1)),
          });
        }
      }
      i = j;
    }
  }

  for (const el of document.querySelectorAll("body *")) {
    if (!visible(el)) continue;
    const cs = getComputedStyle(el);
    if (cs.display === "inline" || cs.display === "inline-block" || cs.display === "contents") continue;
    const text = (el.textContent || "").replace(/\s+/g, " ").trim();
    if (text.length < 3) continue;
    const ch = chWidth(el);
    const w = el.getBoundingClientRect().width;
    if (w > 0 && w < 3 * ch) {
      narrow.push({
        word: text.slice(0, 40),
        tag: el.tagName,
        cls: String(el.className || "").slice(0, 80),
        width: +w.toFixed(1),
        ch: +ch.toFixed(1),
      });
    }
  }

  const overflowNodes = [];
  for (const el of document.querySelectorAll("*")) {
    if (!visible(el)) continue;
    if (el.scrollWidth <= el.clientWidth + 1) continue;
    const cs = getComputedStyle(el);
    if (cs.overflowX === "visible" || cs.overflowX === "clip" || cs.overflowX === "hidden") continue;
    overflowNodes.push({
      tag: el.tagName,
      cls: String(el.className || "").slice(0, 80),
      ow: cs.overflowX,
      sw: el.scrollWidth,
      cw: el.clientWidth,
    });
  }

  return {
    title: document.title,
    pageDelta,
    client: de.clientWidth,
    scroll: de.scrollWidth,
    wordmarks,
    broken: broken.slice(0, 20),
    narrow: narrow.slice(0, 20),
    overflowNodes: overflowNodes.slice(0, 12),
  };
}
"""


def cookie(url: str) -> dict:
    raw = COOKIE_FILE.read_text().strip()
    name, _, value = raw.partition("=")
    if not name or not value:
        raise SystemExit(f"bad cookie file: {COOKIE_FILE}")
    return {"name": name, "value": value, "url": url}


def slug(path: str) -> str:
    return path.strip("/").replace("/", "-") or "root"


def main() -> int:
    if not COOKIE_FILE.exists():
        print(f"missing session cookie: {COOKIE_FILE}", file=sys.stderr)
        return 2
    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    ACCOUNT_AFTER.mkdir(parents=True, exist_ok=True)
    bad = 0
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--disable-gpu"])
        for w in WIDTHS:
            h = 1100 if w >= 800 else 844
            public = browser.new_context(viewport={"width": w, "height": h}, device_scale_factor=1)
            authed = browser.new_context(viewport={"width": w, "height": h}, device_scale_factor=1)
            authed.add_cookies([cookie(BASE)])
            pub_page = public.new_page()
            auth_page = authed.new_page()
            for path in PAGES:
                page = pub_page if path in PUBLIC else auth_page
                resp = page.goto(BASE + path, wait_until="networkidle")
                status = resp.status if resp else 0
                if status >= 400:
                    print(f"HTTP {status} {w} {path}")
                    if status >= 500:
                        bad += 1
                        continue
                page.wait_for_timeout(80)
                info = page.evaluate(JS)
                name = f"{slug(path)}-{w}.png"
                page.screenshot(path=str(SHOT_DIR / name), full_page=True)
                if path == "/admin/accounts":
                    dest = ACCOUNT_AFTER / f"v014-accounts-after-{w}.png"
                    page.screenshot(path=str(dest), full_page=True)
                problems = []
                if info["pageDelta"] > 1:
                    problems.append(f"page overflow delta={info['pageDelta']} scroll={info['scroll']} client={info['client']}")
                if info["wordmarks"]:
                    problems.append(f"wordmark broke: {info['wordmarks']}")
                if info["broken"]:
                    problems.append(f"mid-word wrap: {info['broken']}")
                if info["narrow"]:
                    problems.append(f"narrow text: {info['narrow']}")
                if info["overflowNodes"]:
                    problems.append(f"element overflow: {info['overflowNodes']}")
                if problems:
                    bad += 1
                    print(f"FAIL {w} {path}")
                    for pbl in problems:
                        print(f"  {pbl}")
                else:
                    print(f"ok   {w} {path}")
            public.close()
            authed.close()
        browser.close()
    if bad:
        print(f"{bad} failing page/width combinations")
        return 1
    print("layout audit passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
