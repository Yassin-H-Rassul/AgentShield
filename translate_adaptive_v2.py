"""
Translate adaptive attacks v2 to Kurdish and Arabic using Kagi Translate.

HOW TO USE:
1. Close ALL Chrome windows first
2. Open a terminal and run:
   "C:/Program Files/Google/Chrome/Application/chrome.exe" --remote-debugging-port=9222
3. In Chrome, go to https://translate.kagi.com and solve any Cloudflare challenge
4. Run this script: .venv/Scripts/python translate_adaptive_v2.py
"""
import sys
import json
import re
import time
from playwright.sync_api import sync_playwright

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from agentshield.attacks.adaptive_attacks_v2 import ALL_ADAPTIVE_V2

PLACEHOLDER = "Start typing a URL or some text"


def is_junk(t):
    if not t or len(t) < 10:
        return True
    if PLACEHOLDER in t:
        return True
    if t.startswith("Start typing"):
        return True
    return False


def get_translation(page, text, from_lang, to_lang):
    url = f"https://translate.kagi.com/?from={from_lang}&to={to_lang}"
    page.goto(url, wait_until="networkidle")
    page.wait_for_timeout(2000)

    try:
        textareas = page.locator('textarea').all()
        if textareas:
            textareas[0].click()
            textareas[0].fill("")
            page.wait_for_timeout(300)
            textareas[0].fill(text)
        else:
            editables = page.locator('[contenteditable="true"]').all()
            if editables:
                editables[0].click()
                editables[0].fill("")
                page.wait_for_timeout(300)
                editables[0].fill(text)
            else:
                input_el = page.locator('textarea, [contenteditable="true"], [role="textbox"]').first
                input_el.click()
                page.keyboard.type(text, delay=5)
    except Exception as e:
        print(f"[input error: {e}]", end=" ")
        return None

    page.wait_for_timeout(6000)

    # Strategy 1: Second textarea
    try:
        textareas = page.locator('textarea').all()
        if len(textareas) >= 2:
            t = textareas[1].input_value().strip() if textareas[1].input_value() else ""
            if not is_junk(t) and t != text:
                return t
    except:
        pass

    # Strategy 2: Second contenteditable
    try:
        editables = page.locator('[contenteditable="true"]').all()
        if len(editables) >= 2:
            t = editables[1].inner_text().strip()
            if not is_junk(t) and t != text:
                return t
    except:
        pass

    # Strategy 3: Output selectors
    for sel in ['#output', '.output', '[data-output]', '.translated', '#translated-text', '.result-text', '.translation-output']:
        try:
            el = page.locator(sel).first
            if el.is_visible(timeout=1000):
                t = el.inner_text().strip()
                if not is_junk(t) and t != text:
                    return t
        except:
            pass

    # Strategy 4: RTL text blocks
    try:
        rtl_els = page.locator('[dir="rtl"]').all()
        for el in rtl_els:
            t = el.inner_text().strip()
            if not is_junk(t) and t != text and len(t) > 20:
                return t
    except:
        pass

    # Strategy 5: Arabic/Kurdish script in HTML
    try:
        html = page.content()
        arabic_blocks = re.findall(
            r'(?:[\u0600-\u06FF\u0750-\u077F\uFB50-\uFDFF\uFE70-\uFEFF][\u0600-\u06FF\u0750-\u077F\uFB50-\uFDFF\uFE70-\uFEFF\s\u200c\u200d\u060c\u061f.,:\-()\'\"0-9a-zA-Z@/]*){20,}',
            html
        )
        if arabic_blocks:
            return max(arabic_blocks, key=len).strip()
    except:
        pass

    # Strategy 6: Wait longer and retry
    page.wait_for_timeout(5000)
    try:
        html = page.content()
        arabic_blocks = re.findall(
            r'(?:[\u0600-\u06FF\u0750-\u077F\uFB50-\uFDFF\uFE70-\uFEFF][\u0600-\u06FF\u0750-\u077F\uFB50-\uFDFF\uFE70-\uFEFF\s\u200c\u200d\u060c\u061f.,:\-()\'\"0-9a-zA-Z@/]*){20,}',
            html
        )
        if arabic_blocks:
            return max(arabic_blocks, key=len).strip()
    except:
        pass

    return None


def main():
    # Load existing translations if any (for resuming)
    output_path = "agentshield/attacks/adaptive_v2_translations.json"
    try:
        with open(output_path, encoding="utf-8") as f:
            results = json.load(f)
    except FileNotFoundError:
        results = {"kurdish": {}, "arabic": {}}

    # Only translate payloads we haven't done yet
    to_translate = []
    for attack in ALL_ADAPTIVE_V2:
        aid = attack["id"]
        # Strip the \n\n prefix for translation
        payload = attack["payload"].lstrip("\n")
        if aid not in results["kurdish"] or not results["kurdish"][aid]:
            to_translate.append((aid, payload, "kurdish"))
        if aid not in results["arabic"] or not results["arabic"][aid]:
            to_translate.append((aid, payload, "arabic"))

    if not to_translate:
        print("All 96 translations already done!")
        return

    print(f"Translations remaining: {len(to_translate)} (of 96 total)")
    print()

    with sync_playwright() as p:
        print("Connecting to existing Chrome on localhost:9222...")
        try:
            browser = p.chromium.connect_over_cdp("http://localhost:9222")
        except Exception as e:
            print(f"\nERROR: Could not connect to Chrome: {e}")
            print("\nMake sure you:")
            print("  1. Closed ALL Chrome windows")
            print('  2. Ran: "C:/Program Files/Google/Chrome/Application/chrome.exe" --remote-debugging-port=9222')
            print("  3. Chrome is open and running")
            return

        context = browser.contexts[0]
        page = context.pages[0] if context.pages else context.new_page()
        print(f"Connected! Current page: {page.url}\n")

        lang_map = {"kurdish": "ckb", "arabic": "ar"}

        for i, (aid, payload, lang) in enumerate(to_translate):
            print(f"  [{i+1}/{len(to_translate)}] {aid} → {lang}...", end=" ", flush=True)
            try:
                result = get_translation(page, payload, "en", lang_map[lang])
                if result:
                    results[lang][aid] = result
                    print(f"OK ({len(result)} chars)")
                else:
                    results[lang][aid] = ""
                    print("FAILED")
            except Exception as e:
                results[lang][aid] = ""
                print(f"ERROR: {str(e)[:60]}")

            # Save after each translation (resume-safe)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)

        browser.close()

    # Summary
    ku_ok = sum(1 for v in results["kurdish"].values() if v)
    ar_ok = sum(1 for v in results["arabic"].values() if v)
    print(f"\n{'='*50}")
    print(f"  Kurdish: {ku_ok}/48 successful")
    print(f"  Arabic:  {ar_ok}/48 successful")
    print(f"  Total:   {ku_ok + ar_ok}/96")
    print(f"  Saved:   {output_path}")
    print(f"{'='*50}")

    # Show failures
    failures = []
    for lang in ["kurdish", "arabic"]:
        for aid, val in results[lang].items():
            if not val:
                failures.append(f"  {aid} ({lang})")
    if failures:
        print(f"\nFailed translations ({len(failures)}):")
        for f in failures:
            print(f)


if __name__ == "__main__":
    main()
