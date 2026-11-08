"""UI smoke test + screenshots (desktop and phone) against the test stack. Fails on any JS error.
Run in mcr.microsoft.com/playwright/python: USM_UI_URL=http://frontend:8080 python screens.py /out"""
import os
import sys

from playwright.sync_api import sync_playwright

URL, OUT = os.environ["USM_UI_URL"], sys.argv[1]
SIZES = {"desktop": (1366, 850), "phone": (390, 844)}

with sync_playwright() as p:
    browser = p.chromium.launch()
    for name, (w, h) in SIZES.items():
        page = browser.new_page(viewport={"width": w, "height": h})
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("console", lambda m: m.type == "error" and errors.append(m.text))

        page.goto(f"{URL}/#/login"); page.wait_for_selector("text=DEV LOGIN")
        page.screenshot(path=f"{OUT}/{name}-1-login.png")
        page.fill("input[type=email]", "admin@example.com"); page.click("text=Sign in (dev)")
        page.wait_for_selector("text=stg--api"); page.screenshot(path=f"{OUT}/{name}-2-bundles.png", full_page=True)
        page.click("text=stg--api"); page.wait_for_selector("text=DB_PASSWORD")
        page.screenshot(path=f"{OUT}/{name}-3-keys.png", full_page=True)
        assert "seed-value" not in page.content(), "secret value visible in the page"
        page.click("button:has-text('View') >> nth=0"); page.wait_for_selector("dialog[open]")
        page.fill("input[name=reason]", "UI smoke test"); page.click("#dlg-ok"); page.wait_for_selector("text=masked by default")
        page.screenshot(path=f"{OUT}/{name}-3b-reveal-masked.png")
        assert "seed-value" not in page.inner_text("dialog"), "revealed value not masked by default"
        page.click("dialog button:has-text('Show')")
        assert "seed-value" in page.inner_text("dialog"), "Show did not unmask"
        page.click("#dlg-cancel")
        assert "seed-value" not in page.content(), "value left in the page after closing"
        page.click("button:has-text('Update') >> nth=0"); page.wait_for_selector("dialog[open]")
        page.screenshot(path=f"{OUT}/{name}-4-update-dialog.png")
        page.click("#dlg-cancel")
        page.click("text=Versions"); page.wait_for_selector("text=current")
        page.screenshot(path=f"{OUT}/{name}-5-versions.png", full_page=True)
        page.goto(f"{URL}/#/users"); page.wait_for_selector("table >> text=admin@example.com")
        page.screenshot(path=f"{OUT}/{name}-6-users.png", full_page=True)
        page.goto(f"{URL}/#/audit"); page.wait_for_selector("text=Audit log")
        page.screenshot(path=f"{OUT}/{name}-7-audit.png", full_page=True)
        width = page.evaluate("document.documentElement.scrollWidth")
        assert width <= w + 1, f"{name}: page scrolls horizontally ({width}px > {w}px)"
        assert not errors, f"{name}: browser errors: {errors}"
        print(f"{name}: ok, no JS errors, no horizontal scroll")
        page.close()

    # role checks in the browser: viewer = names only, editor = add/update only (users created by the API tests)
    expect = {"viewer@example.com": {"View": 0, "Update": 0, "Delete": 0, "Add key": 0},
              "editor@example.com": {"View": 0, "Update": 1, "Delete": 0, "Add key": 1}}
    for email, want in expect.items():
        page = browser.new_page(viewport={"width": 1366, "height": 850})
        page.goto(f"{URL}/#/login"); page.wait_for_selector("text=DEV LOGIN")
        page.fill("input[type=email]", email); page.click("text=Sign in (dev)")
        page.wait_for_selector("text=stg--api"); page.click("text=stg--api"); page.wait_for_selector("text=DB_PASSWORD")
        got = {b: page.locator(f"button:has-text('{b}')").count() for b in want}
        ok = all((got[b] > 0) == bool(want[b]) for b in want)
        assert ok, f"{email}: buttons {got}, expected {want}"
        assert page.locator("nav a:has-text('Users')").is_hidden() and page.locator("nav a:has-text('Audit')").is_hidden()
        page.screenshot(path=f"{OUT}/role-{email.split('@')[0]}-keys.png", full_page=True)
        print(f"{email.split('@')[0]}: buttons {got} - ok")
        page.close()
    browser.close()
