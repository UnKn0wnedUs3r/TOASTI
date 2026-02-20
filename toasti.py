from __future__ import annotations

import argparse
import sys

from tqdm import tqdm

from core.http import HTTPClient
from core.spider import crawl_site
from core.targets import build_targets_from_forms_index
from core.auth import perform_login

# engines
from engines.reflection import reflection_probe
from engines.ssti_jinja2 import jinja2_ssti_scan
from engines.ssti_twig import twig_ssti_scan
from engines.ssti_freemarker import freemarker_ssti_scan
from engines.ssti_velocity import velocity_ssti_scan
from engines.ssti_mustache import mustache_ssti_scan
from engines.os_injection import os_injection_scan


# ============================================================
# PRINT TARGETS
# ============================================================

def print_targets(targets):

    print("\n========== TARGETS ==========\n")

    for t in targets:

        print(f"{t.method} {t.url} {t.params}")

    print()


# ============================================================
# PRINT REFLECTION RESULTS
# ============================================================

def print_reflection(results):

    print("\n========== Reflection ==========\n")

    for r in results:

        url = r["target"]["url"]
        param = r["param"]

        if r.get("reflected"):

            result = "Reflected"

        else:

            result = "Not Reflected"

        print(f"Target     : {url}")
        print(f"Parameter  : {param}")
        print(f"Result     : {result}")
        print("----------------------------------------")

    print()


# ============================================================
# PRINT SSTI RESULTS
# ============================================================

def print_ssti(name, results):

    print(f"\n========== SSTI Summary ({name}) ==========\n")

    total = 0
    vuln = 0

    for r in results:

        total += 1

        url = r["target"]["url"]
        param = r["param"]

        verdict = r["verdict"]["vulnerable"]

        if verdict:

            vuln += 1
            result = "VULNERABLE"

        else:

            result = "Not Vulnerable"

      

        print(f"Target     : {url}")
        print(f"Parameter  : {param}")
        print(f"Result     : {result}")
    
        print("----------------------------------------")

    print(f"\nSummary: {vuln} / {total} vulnerable\n")


# ============================================================
# PROGRESS WRAPPER
# ============================================================

def run_with_progress(label, func, client, targets):

    print(f"[+] Running {label}")

    results = []

    with tqdm(total=len(targets), desc=f"{label} Progress") as pbar:

        for t in targets:

            r = func(client, [t])

            if r:
                results.extend(r)

            pbar.update(1)

    return results


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("-u", "--url", required=True)

    parser.add_argument("--depth", type=int, default=2)

    parser.add_argument("--login-url")
    parser.add_argument("--user")
    parser.add_argument("--pass", dest="password")

    parser.add_argument("--show-targets", action="store_true")

    parser.add_argument("--reflect", action="store_true")

    parser.add_argument("--ssti-jinja2", action="store_true")
    parser.add_argument("--ssti-twig", action="store_true")
    parser.add_argument("--ssti-freemarker", action="store_true")
    parser.add_argument("--ssti-velocity", action="store_true")
    parser.add_argument("--ssti-mustache", action="store_true")

    parser.add_argument("--os-inject", action="store_true")

    args = parser.parse_args()


    print(f"[+] Starting Toasti against {args.url}")


    client = HTTPClient()


    # LOGIN

    if args.login_url:

        print("[+] Attempting login...")

        ok = perform_login(
            client,
            args.login_url,
            args.user,
            args.password,
        )

        if ok:

            print("[+] Login success")

        else:

            print("[!] Login failed")
            sys.exit(1)


    # CRAWL

    print("[+] Crawling target")

    crawl = crawl_site(
        client,
        args.url,
        depth=args.depth,
    )


    # BUILD TARGETS

    targets = build_targets_from_forms_index(

        forms_index=crawl.get("forms_index"),

        api_endpoints=crawl.get("api_endpoints"),

        openapi_targets=crawl.get("openapi_targets"),

        base_url=args.url,

        query_urls=crawl.get("query_urls"),

    )


    print(f"[+] Total targets: {len(targets)}")


    if args.show_targets:

        print_targets(targets)


    if not targets:

        print("\n[!] No scan targets built.")


    # REFLECTION

    if args.reflect:

        results = run_with_progress(
            "Reflection",
            reflection_probe,
            client,
            targets
        )

        print_reflection(results)


    # SSTI

    if args.ssti_jinja2:

        results = run_with_progress(
            "Jinja2 SSTI",
            jinja2_ssti_scan,
            client,
            targets
        )

        print_ssti("jinja2", results)


    if args.ssti_twig:

        results = run_with_progress(
            "Twig SSTI",
            twig_ssti_scan,
            client,
            targets
        )

        print_ssti("twig", results)


    if args.ssti_freemarker:

        results = run_with_progress(
            "FreeMarker SSTI",
            freemarker_ssti_scan,
            client,
            targets
        )

        print_ssti("freemarker", results)


    if args.ssti_velocity:

        results = run_with_progress(
            "Velocity SSTI",
            velocity_ssti_scan,
            client,
            targets
        )

        print_ssti("velocity", results)


    if args.ssti_mustache:

        results = run_with_progress(
            "Mustache SSTI",
            mustache_ssti_scan,
            client,
            targets
        )

        print_ssti("mustache", results)


    if args.os_inject:

        results = run_with_progress(
            "OS Injection",
            os_injection_scan,
            client,
            targets
        )

        print_ssti("os injection", results)


    print("[+] Scan complete")


# ============================================================

if __name__ == "__main__":

    main()
