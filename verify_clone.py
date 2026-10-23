"""Checks a clone offline: serves it locally, visits its pages and reports external requests / 4xx on local ones."""
import sys, json, urllib.parse
from pathlib import Path
from site_server import make_server
from cloner import launch
import threading
from playwright.sync_api import sync_playwright

def verify(root, port, max_pages=12):
    root = Path(root)
    httpd = make_server(root, port)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    external, bad, errors, visited = set(), set(), [], []
    with sync_playwright() as pw:
        b = launch(pw, ["--use-angle=swiftshader", "--enable-unsafe-swiftshader", "--ignore-gpu-blocklist"])
        ctx = b.new_context(service_workers="block")
        def route(r):
            u = r.request.url
            if u.startswith(base) or u.startswith("data:") or u.startswith("blob:"):
                r.continue_()
            else:
                external.add(u.split("?")[0][:120]); r.abort()
        ctx.route("**/*", route)
        queue, seen = [base + "/"], {base + "/"}
        while queue and len(visited) < max_pages:
            u = queue.pop(0)
            p = ctx.new_page()
            p.on("response", lambda r: bad.add(r.url[:120]) if r.status >= 400 else None)
            p.on("pageerror", lambda e: errors.append(str(e)[:120]))
            try:
                p.goto(u, wait_until="load", timeout=45000)
                try: p.wait_for_load_state("networkidle", timeout=10000)
                except Exception: pass
                p.wait_for_timeout(3000)
                visited.append((u, len(p.inner_text("body")), p.title()))
                for h in p.eval_on_selector_all("a[href]", "e=>e.map(x=>x.href)"):
                    h = urllib.parse.urldefrag(h)[0]
                    if h.startswith(base) and h not in seen:
                        seen.add(h); queue.append(h)
            except Exception as e:
                errors.append(f"{u}: {e}"[:150])
            p.close()
        b.close()
    httpd.shutdown()
    return {"pages": visited, "external": sorted(external), "bad": sorted(bad), "errors": errors[:8]}

if __name__ == "__main__":
    r = verify(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 4990)
    print(json.dumps(r, indent=1, ensure_ascii=False))
