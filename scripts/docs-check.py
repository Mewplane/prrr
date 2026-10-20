#!/usr/bin/env python3
"""Build and exercise the documentation as a reader.

FRD: specs/frds/FRD-illustrated-documentation.md
Run using the Python environment installed from requirements-docs.txt.
"""
from functools import partial
from html.parser import HTMLParser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import unquote, urlsplit
import subprocess
import sys

from playwright.sync_api import expect, sync_playwright
from yaml import safe_load

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "target" / "docs-site"
SITE_PREFIX = urlsplit(safe_load((ROOT / "mkdocs.yml").read_text()).get("site_url", "")).path.rstrip("/")
PREVIEW = ROOT / "target" / "docs-preview"
MECHANICS = "explanation/mechanics/"
LAST_STAGES = {
    "handshake": "Tunnel ready",
    "packets": "Reject a replay",
    "routing": "Restore the session",
}
CHAPTER_COUNTS = {"handshake": 7, "packets": 8, "routing": 7}
TOTAL_STEPS = sum(CHAPTER_COUNTS.values())


class Links(HTMLParser):
    """Collect local anchors for validation against the built output."""

    def __init__(self):
        super().__init__()
        self.targets = []
        self.ids = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        if tag == "a" and attrs.get("href"):
            self.targets.append(attrs["href"])


def check_links():
    documents = {}
    for path in SITE.rglob("*.html"):
        parser = Links()
        parser.feed(path.read_text())
        documents[path.resolve()] = parser
    for path, parser in documents.items():
        for href in parser.targets:
            link = urlsplit(href)
            if link.scheme or link.netloc:
                continue
            target = (path.parent / unquote(link.path)).resolve() if link.path else path
            if link.path.startswith("/"):
                site_path = unquote(link.path)
                if SITE_PREFIX and site_path.startswith(SITE_PREFIX + "/"):
                    site_path = site_path[len(SITE_PREFIX):]
                target = (SITE / site_path.lstrip("/")).resolve()
            if target.is_dir():
                target /= "index.html"
            assert target.is_relative_to(SITE), f"Link escapes site: {path}: {href}"
            assert target.exists(), f"Broken link: {path}: {href}"
            if link.fragment and target in documents:
                assert unquote(link.fragment) in documents[target].ids, f"Missing anchor: {path}: {href}"
    print(f"PASS local links and anchors ({len(documents)} HTML pages)")


def no_overflow(page):
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "Horizontal page overflow"


def check_rich_diagrams(page, base):
    page.goto(base + MECHANICS)
    wide_views = {}
    for flow in LAST_STAGES:
        widget = page.locator(f'.sy-mechanics[data-flow="{flow}"]')
        scene = widget.locator("svg.sy-scene[role=img]")
        expect(scene).to_be_visible()
        expect(scene).to_have_attribute("data-layout", "landscape")
        wide_views[flow] = scene.get_attribute("viewBox")
        name = scene.get_attribute("aria-label") or scene.get_attribute("aria-labelledby")
        assert name, "Illustrated scenes need an accessible description"
        actor_names = {"handshake": ["client", "server"], "packets": ["application", "tun", "relay", "destination"], "routing": ["policy", "tunnel", "internet"]}[flow]
        for actor in actor_names:
            expect(scene.locator(f'[data-node="{actor}"]')).to_be_visible()
        assert scene.locator("[data-channel]").count() >= 2, "Scenes need labeled message routes"
        assert scene.locator('[data-channel][data-visible="false"]').count() >= 1, "Future message routes must be progressively revealed"
        expect(widget).to_have_attribute("data-step", "0")
        chapters = widget.locator(".sy-chapter")
        expected_steps = CHAPTER_COUNTS[flow]
        expect(chapters).to_have_count(expected_steps)
        expect(chapters.first).to_have_attribute("aria-current", "step")
        speed = widget.get_by_label("Playback speed", exact=True)
        expect(speed).to_have_value("1")
        assert set(speed.locator("option").evaluate_all("items => items.map(e => e.value)")) == {"0.75", "1", "1.5"}
    print("PASS illustrated actors, accessible scenes, message routes, chapters and playback speeds")
    return wide_views


def check_flows(page, base):
    page.goto(base + MECHANICS)
    for name, last_stage in LAST_STAGES.items():
        widget = page.locator(f'.sy-mechanics[data-flow="{name}"]')
        expect(widget.get_by_role("button", name="Play", exact=True)).to_be_visible()
        expect(widget.locator(".sy-mechanics__counter")).to_contain_text("Step 1 of")
        next_step = widget.get_by_role("button", name="Next step", exact=True)
        visited = 1
        while next_step.is_enabled():
            next_step.click()
            visited += 1
            assert visited <= 12, "Flow did not finish"
        expect(widget.locator(".sy-mechanics__stage strong")).to_have_text(last_stage)
        expect(widget.get_by_role("button", name="Play", exact=True)).to_be_disabled()
        widget.get_by_role("button", name="Restart", exact=True).click()
        expect(widget.locator(".sy-mechanics__counter")).to_contain_text("Step 1 of")
        print(f"PASS {name}: {visited} readable steps, completion and restart")


def contrast_ratio(first, second):
    def luminance(values):
        channels = [v / 255 for v in values[:3]]
        linear = [v / 12.92 if v <= .04045 else ((v + .055) / 1.055) ** 2.4 for v in channels]
        return sum(v * weight for v, weight in zip(linear, [.2126, .7152, .0722]))
    foreground, background = luminance(first), luminance(second)
    return (max(foreground, background) + .05) / (min(foreground, background) + .05)


def check_contrast(page):
    selectors = [".md-typeset", ".md-nav__link", ".sy-mechanics__title",
                 ".sy-mechanics__actor", ".sy-mechanics__stage strong",
                 ".sy-mechanics__controls button", ".sy-mechanics__motion-note",
                 ".sy-hero .md-button", ".sy-eyebrow",
                 "article h1", "article h2", "article > p", "article code", "article th", "article td"]
    for selector in selectors:
        for node in page.locator(selector).all():
            if not node.is_visible():
                continue
            colors = node.evaluate(r"""e => {
                const rgb = value => value.match(/[\d.]+/g).map(Number);
                let background = e;
                while (background.parentElement && getComputedStyle(background).backgroundColor === 'rgba(0, 0, 0, 0)') background = background.parentElement;
                return {fg:rgb(getComputedStyle(e).color), bg:rgb(getComputedStyle(background).backgroundColor)};
            }""")
            ratio = contrast_ratio(colors["fg"], colors["bg"])
            assert ratio >= 4.5, f"Unreadable text contrast {ratio:.2f}: {selector} {node.inner_text()}"
    print("PASS representative navigation, explanation and control contrast")


def check_svg_contrast(page):
    for scene in page.locator("svg.sy-scene").all():
        colors = scene.evaluate(r"""scene => {
            const rgb=value => value.match(/[\d.]+/g)?.map(Number);
            const visible=e => {
                for(let n=e; n; n=n.parentElement) {
                    const s=getComputedStyle(n);
                    if(s.display==='none'||s.visibility==='hidden'||Number(s.opacity)<0.1) return false;
                }
                return true;
            };
            return Array.from(scene.querySelectorAll('text')).filter(visible).map(e => {
                const box=e.getBoundingClientRect(), x=box.x+box.width/2,y=box.y+box.height/2;
                const backgrounds=Array.from(scene.querySelectorAll('rect')).filter(r => {
                    const b=r.getBoundingClientRect(), f=getComputedStyle(r).fill;
                    return visible(r) && f.startsWith('rgb') && (r.compareDocumentPosition(e)&Node.DOCUMENT_POSITION_FOLLOWING) && b.x<=x && x<=b.right && b.y<=y && y<=b.bottom;
                });
                const background=backgrounds.at(-1);
                return {label:e.textContent,fg:rgb(getComputedStyle(e).fill),bg:background?rgb(getComputedStyle(background).fill):[0,0,0]};
            });
        }""")
        for label in colors:
            assert label["fg"], f"SVG text needs a visible fill: {label['label']}"
            ratio = contrast_ratio(label["fg"], label["bg"])
            assert ratio >= 4.5, f"Unreadable diagram text contrast {ratio:.2f}: {label['label']}"
    print("PASS painted SVG label contrast against device and packet surfaces")


def scene_text(widget, text, exact=True):
    label = widget.locator(".sy-scene").locator("text").get_by_text(text, exact=exact).first
    expect(label).to_be_visible()
    assert label.evaluate("""e => {
        for (let n=e; n; n=n.parentElement) {
            const style=getComputedStyle(n);
            if (style.display==='none' || style.visibility==='hidden' || Number(style.opacity)<0.1) return false;
        }
        return true;
    }"""), f"Illustrated label is hidden: {text}"


def packet_position(widget):
    packet = widget.locator("[data-packet]").first
    expect(packet).to_be_visible()
    return packet.evaluate("e => {const p=e.getBoundingClientRect(); return {x:p.x,y:p.y};}")


def no_visual_motion(widget):
    states = widget.evaluate("""e => e.getAnimations({subtree:true}).map(a => ({
        state:a.playState, rate:a.playbackRate
    }))""")
    assert not any(a["state"] == "running" and a["rate"] != 0 for a in states), "Reduced motion must stop visual Web Animations and CSS animations"
    movement = widget.evaluate("""async e => {
        const packet=e.querySelector('[data-packet]');
        if(!packet) return 0;
        const first=packet.getBoundingClientRect();
        await new Promise(resolve => setTimeout(resolve, 500));
        const last=packet.getBoundingClientRect();
        return Math.abs(last.x-first.x)+Math.abs(last.y-first.y);
    }""")
    assert movement < 1, "Reduced motion must also stop requestAnimationFrame packet movement"


def seek(widget, index):
    chapter = widget.locator(".sy-chapter").nth(index)
    chapter.click()
    expect(widget).to_have_attribute("data-step", str(index))
    expect(chapter).to_have_attribute("aria-current", "step")
    expect(widget.locator('.sy-chapter[aria-current="step"]')).to_have_count(1)


def check_actor_labels(widget):
    for actor in widget.locator("[data-node]").all():
        body = actor.locator(".sy-device__body").bounding_box()
        for label in actor.locator("text").all():
            if not label.is_visible():
                continue
            bounds = label.bounding_box()
            assert bounds["x"] >= body["x"]+4 and bounds["x"]+bounds["width"] <= body["x"]+body["width"]-4, f"Actor label touches its side: {label.text_content()}"
            assert bounds["y"] >= body["y"]+4 and bounds["y"]+bounds["height"] <= body["y"]+body["height"]-4, f"Actor label touches its bottom: {label.text_content()}"


def check_chapters_and_payloads(page):
    for flow in LAST_STAGES:
        widget = page.locator(f'.sy-mechanics[data-flow="{flow}"]')
        for index in range(CHAPTER_COUNTS[flow]):
            seek(widget, index)
            stage = widget.locator(".sy-mechanics__stage")
            assert len(stage.inner_text().strip()) > 40, "Every chapter needs a complete explanation"
            check_actor_labels(widget)
            check_svg_contrast(page)
        widget.get_by_role("button", name="Previous step", exact=True).focus()
        page.keyboard.press("Enter")
        expect(widget).to_have_attribute("data-step", str(CHAPTER_COUNTS[flow]-2))
        expect(widget.get_by_role("button", name="Previous step", exact=True)).to_be_focused()
        chapter = widget.locator(".sy-chapter").nth(2)
        chapter.focus()
        page.keyboard.press("Space")
        expect(widget).to_have_attribute("data-step", "2")
        expect(chapter).to_be_focused()
        widget.screenshot(path=str(PREVIEW / f"desktop-{flow}.png"), style=".md-header, .md-top { visibility: hidden !important; }")
        widget.get_by_role("button", name="Restart", exact=True).click()
        expect(widget.get_by_role("button", name="Previous step", exact=True)).to_be_disabled()
    handshake = page.locator('.sy-mechanics[data-flow="handshake"]')
    seek(handshake, 2)
    scene_text(handshake, "ML-KEM-768 encapsulate")
    scene_text(handshake, "Noise IK: e, es, s, ss")
    seek(handshake, 5)
    for label in ["HKDF-SHA256", "tx_key / rx_key"]:
        scene_text(handshake, label)
    packets = page.locator('.sy-mechanics[data-flow="packets"]')
    seek(packets, 1)
    for part in ["nonce", "ciphertext", "tag"]:
        expect(packets.locator(f'[data-part="{part}"]')).to_be_visible()
    scene_text(packets, "counter · 8 B")
    scene_text(packets, "tag · 16 B")
    seek(packets, 2)
    scene_text(packets, "HARP · TCP/443", exact=False)
    scene_text(packets, "MASQUE · UDP/443", exact=False)
    seek(packets, 7)
    scene_text(packets, "Replay rejected · duplicate counter 42")
    routing = page.locator('.sy-mechanics[data-flow="routing"]')
    seek(routing, 3)
    scene_text(routing, "Host DNS retained")
    seek(routing, 6)
    scene_text(routing, "Fresh session keys")
    scene_text(routing, "Same TUN device")
    for widget in [handshake, packets, routing]:
        widget.get_by_role("button", name="Restart", exact=True).click()
    print(f"PASS all {TOTAL_STEPS} chapters, source-accurate payloads, routing gates, contrast, focus and keyboard seeking")


def check_playback(page):
    widget = page.locator('.sy-mechanics[data-flow="packets"]')
    counter = widget.locator(".sy-mechanics__counter")
    seek(widget, 3)
    widget.get_by_label("Playback speed", exact=True).select_option("0.75")
    widget.get_by_role("button", name="Play", exact=True).click()
    expect(widget).to_have_attribute("data-playing", "true")
    page.wait_for_timeout(300)
    before = packet_position(widget)
    page.wait_for_timeout(500)
    after = packet_position(widget)
    assert abs(after["x"]-before["x"]) + abs(after["y"]-before["y"]) > 2, "Playing must animate a real SVG message packet"
    widget.get_by_role("button", name="Pause", exact=True).click()
    expect(widget).to_have_attribute("data-playing", "false")
    paused = counter.text_content()
    frozen = packet_position(widget)
    page.wait_for_timeout(600)
    after_pause = packet_position(widget)
    assert abs(after_pause["x"]-frozen["x"]) + abs(after_pause["y"]-frozen["y"]) < 1, "Pause must freeze packet movement"
    page.wait_for_timeout(3100)
    expect(counter).to_have_text(paused)
    widget.get_by_role("button", name="Play", exact=True).click()
    expect(counter).not_to_have_text(paused, timeout=9500)
    widget.get_by_role("button", name="Pause", exact=True).click()
    widget.get_by_role("button", name="Restart", exact=True).focus()
    page.keyboard.press("Enter")
    expect(counter).to_contain_text("Step 1 of")
    widget.get_by_role("button", name="Next step", exact=True).focus()
    page.keyboard.press("Space")
    expect(counter).to_contain_text("Step 2 of")
    widget.get_by_role("button", name="Play", exact=True).click()
    page.emulate_media(reduced_motion="reduce")
    expect(widget.get_by_role("button", name="Play", exact=True)).to_be_visible()
    expect(widget.locator(".sy-mechanics__motion-note")).to_contain_text("Reduced motion")
    no_visual_motion(widget)
    page.emulate_media(reduced_motion="no-preference")
    widget.get_by_role("button", name="Restart", exact=True).click()
    widget.get_by_role("button", name="Play", exact=True).click()
    # Chromium under automation reports every tab as visible here. Inject only
    # the visibility signal; exercise the real component listener and timer.
    page.evaluate("""() => {
        Object.defineProperty(document, 'hidden', {configurable: true, get: () => true});
        document.dispatchEvent(new Event('visibilitychange'));
    }""")
    expect(widget.get_by_role("button", name="Play", exact=True)).to_be_visible()
    paused = counter.text_content()
    page.wait_for_timeout(3100)
    expect(counter).to_have_text(paused)
    page.evaluate("delete document.hidden")
    print("PASS SVG packet motion/freeze, playback, pause, keyboard, reduced motion and simulated hidden-document event")


def check_final_delivery(page):
    widget = page.locator('.sy-mechanics[data-flow="packets"]')
    last = CHAPTER_COUNTS["packets"]-1
    seek(widget, last-1)
    widget.get_by_label("Playback speed", exact=True).select_option("1.5")
    widget.get_by_role("button", name="Play", exact=True).click()
    expect(widget).to_have_attribute("data-step", str(last), timeout=6500)
    expect(widget.get_by_role("button", name="Pause", exact=True)).to_be_enabled()
    expect(widget).to_have_attribute("data-playing", "true")
    before = packet_position(widget)
    page.wait_for_timeout(500)
    after = packet_position(widget)
    assert abs(after["x"]-before["x"]) + abs(after["y"]-before["y"]) > 1, "The final replay attempt must animate before playback completes"
    expect(widget.get_by_role("button", name="Play", exact=True)).to_be_disabled(timeout=6500)
    expect(widget).to_have_attribute("data-playing", "false")
    expect(widget.locator(".sy-mechanics__stage strong")).to_have_text(LAST_STAGES["packets"])
    widget.get_by_role("button", name="Restart", exact=True).click()
    print("PASS final replay attempt animates before rejection and completion")


def check_reduced(browser, base):
    context = browser.new_context(reduced_motion="reduce")
    page = context.new_page()
    page.goto(base + MECHANICS)
    widget = page.locator('.sy-mechanics[data-flow="routing"]')
    expect(widget.get_by_role("button", name="Play", exact=True)).to_be_visible()
    expect(widget).to_have_attribute("data-playing", "false")
    seek(widget, 1)
    widget.get_by_role("button", name="Play", exact=True).click()
    no_visual_motion(widget)
    expect(widget.locator(".sy-mechanics__motion-note")).to_contain_text("Reduced motion")
    context.close()
    print("PASS initial reduced motion and motion-free playback")


def check_portrait_scene(scene, wide_view):
    expect(scene).not_to_have_attribute("viewBox", wide_view)
    geometry = scene.evaluate("""scene => {
        const bounds=scene.getBoundingClientRect();
        const labels=Array.from(scene.querySelectorAll('text')).map(e => {
            let visible=true;
            for(let n=e; n; n=n.parentElement) {
                const s=getComputedStyle(n);
                if(s.display==='none'||s.visibility==='hidden'||Number(s.opacity)<0.1) visible=false;
            }
            const m=e.getScreenCTM(),r=e.getBoundingClientRect();
            return {label:e.textContent,visible,size:parseFloat(getComputedStyle(e).fontSize)*Math.hypot(m.a,m.b),x:r.x,y:r.y,width:r.width,height:r.height};
        });
        return {bounds:{x:bounds.x,y:bounds.y,width:bounds.width,height:bounds.height},labels};
    }""")
    bounds = geometry["bounds"]
    assert bounds["height"] > bounds["width"], "Narrow screens need a portrait scene layout"
    for label in geometry["labels"]:
        if not label["visible"]:
            continue
        assert label["size"] >= 11.5, f"Narrow scene label is too small: {label['label']}"
        assert label["x"] >= bounds["x"]-2 and label["x"]+label["width"] <= bounds["x"]+bounds["width"]+2, f"Clipped scene label: {label['label']}"
        assert label["y"] >= bounds["y"]-2 and label["y"]+label["height"] <= bounds["y"]+bounds["height"]+2, f"Vertically clipped scene label: {label['label']}"


def check_all_narrow_steps(page, wide_views):
    for flow in LAST_STAGES:
        widget = page.locator(f'.sy-mechanics[data-flow="{flow}"]')
        for index in range(widget.locator(".sy-chapter").count()):
            seek(widget, index)
            check_portrait_scene(widget.locator("svg.sy-scene"), wide_views[flow])
            check_actor_labels(widget)
        widget.get_by_role("button", name="Restart", exact=True).click()


def check_tablet(browser, base, wide_views):
    context = browser.new_context(viewport={"width": 820, "height": 1180}, has_touch=True)
    page = context.new_page()
    page.goto(base + MECHANICS)
    no_overflow(page)
    check_all_narrow_steps(page, wide_views)
    page.locator('.sy-mechanics[data-flow="packets"]').screenshot(path=str(PREVIEW / "tablet-packets.png"), style=".md-header, .md-top { visibility: hidden !important; }")
    context.close()
    print(f"PASS tablet portrait reflow, readable labels and unclipped scenes across all {TOTAL_STEPS} steps")


def check_plain_and_mobile(browser, base, wide_views):
    context = browser.new_context(java_script_enabled=False)
    page = context.new_page()
    page.goto(base + MECHANICS)
    expect(page.locator("article")).to_contain_text("ML-KEM")
    assert page.locator("article ol li").count() >= 10, "Complete numbered transcripts are required"
    for widget in page.locator(".sy-mechanics").all():
        expect(widget).to_be_hidden()
    context.close()
    context = browser.new_context(viewport={"width": 375, "height": 812}, is_mobile=True, has_touch=True)
    page = context.new_page()
    for path in ["", MECHANICS]:
        page.goto(base + path)
        no_overflow(page)
        if not path:
            page.screenshot(path=str(PREVIEW / "mobile-home.png"), full_page=True)
    check_all_narrow_steps(page, wide_views)
    widget = page.locator('.sy-mechanics[data-flow="handshake"]')
    for button in widget.get_by_role("button").all() + [widget.get_by_label("Playback speed", exact=True)]:
        bounds = button.bounding_box()
        assert bounds["height"] >= 44 and bounds["width"] >= 44, "Mobile touch controls need 44px targets"
    widget.get_by_role("button", name="Next step", exact=True).click()
    expect(widget.locator(".sy-mechanics__counter")).to_contain_text("Step 2 of")
    widget.screenshot(path=str(PREVIEW / "mobile-handshake.png"), style=".md-header, .md-top { visibility: hidden !important; }")
    approval = page.locator('.sy-mechanics[data-flow="packets"]')
    seek(approval, 2)
    approval.screenshot(path=str(PREVIEW / "mobile-packets.png"), style=".md-header, .md-top { visibility: hidden !important; }")
    page.screenshot(path=str(PREVIEW / "mobile-mechanics.png"), full_page=True)
    context.close()
    print("PASS script-free transcripts, hidden empty widgets and mobile layout")


def check_search(page, base):
    page.goto(base)
    logo = page.locator(".sy-hero img")
    expect(logo).to_be_visible()
    assert logo.evaluate("image => image.complete && image.naturalWidth > 0"), "The project mascot must load on the landing page"
    check_contrast(page)
    page.locator("input.md-search__input").fill("ML-KEM")
    expect(page.locator(".md-search-result__item").first).to_be_visible(timeout=10000)
    print("PASS local search returns protocol results")


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


def main():
    assert (ROOT / "mkdocs.yml").is_file(), "Documentation needs a MkDocs site configuration"
    subprocess.run([sys.executable, "-m", "mkdocs", "build", "--strict"], cwd=ROOT, check=True)
    check_links()
    PREVIEW.mkdir(parents=True, exist_ok=True)
    handler = partial(QuietHandler, directory=str(SITE))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}/"
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(args=["--disable-gpu"])
            context = browser.new_context(viewport={"width": 1440, "height": 1000})
            external = []
            def local_only(route):
                if route.request.url.startswith(base):
                    route.continue_()
                else:
                    external.append(route.request.url)
                    route.abort()
            context.route("**/*", local_only)
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            wide_views = check_rich_diagrams(page, base)
            check_flows(page, base)
            check_chapters_and_payloads(page)
            check_svg_contrast(page)
            check_contrast(page)
            assert not external, f"Unexpected external asset requests: {external}"
            no_overflow(page)
            check_playback(page)
            check_final_delivery(page)
            check_search(page, base)
            page.keyboard.press("Escape")
            page.screenshot(path=str(PREVIEW / "desktop-home.png"), full_page=True)
            page.goto(base + MECHANICS)
            page.screenshot(path=str(PREVIEW / "desktop-mechanics.png"), full_page=True)
            check_reduced(browser, base)
            check_plain_and_mobile(browser, base, wide_views)
            check_tablet(browser, base, wide_views)
            page.emulate_media(media="print")
            check_contrast(page)
            for widget in page.locator(".sy-mechanics").all():
                expect(widget).to_be_hidden()
            print("PASS print contrast and hidden illustrations with complete transcripts")
            assert not external, f"Unexpected external asset requests: {external}"
            assert not errors, f"Browser errors: {errors}"
            context.close()
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    print("Documentation checks passed")


if __name__ == "__main__":
    main()
