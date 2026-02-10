import argparse
import json
import sys
from typing import Any, Dict, List

from core.http import HTTPClient
from core.spider import crawl_site
from core.targets import build_targets_from_forms_index, Target
from core.auth import authenticate_form

from engines.reflection import reflection_probe
from engines.ssti_jinja2 import jinja2_ssti_scan
from engines.os_injection import os_injection_scan

from engines.ssti_twig import twig_ssti_scan
from engines.ssti_freemarker import freemarker_ssti_scan
from engines.ssti_velocity import velocity_ssti_scan
from engines.ssti_mustache import mustache_ssti_scan


def _parse_kv_list(items: List[str] | None) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for it in items or []:
        if "=" not in it:
            raise ValueError(f"Expected key=value, got: {it}")
        k, v = it.split("=", 1)
        out[k.strip()] = v
    return out


def _print_targets(targets: List[Target]) -> None:
    if not targets:
        print("\n[!] No scan targets built (nothing to test).")
        return

    targets_sorted = sorted(targets, key=lambda t: (t.url, t.method, ",".join(t.params or []), t.source_page))

    print("\n========== Scan Targets (Unique Injection Points) ==========\n")
    print(f"[+] Total unique targets: {len(targets_sorted)}\n")

    for t in targets_sorted:
        params = t.params or []
        params_str = ", ".join(params) if params else "(no params)"
        src = t.source_page or ""
        j = " JSON" if t.is_json else ""
        hidden_str = f" hidden=[{', '.join(sorted(t.hidden.keys()))}]" if t.hidden else ""

        print(f"- {t.method}{j}  {t.url}")
        print(f"    params=[{params_str}]{hidden_str}")
        if src:
            print(f"    discovered_from={src}")
        print()

    print("===========================================================\n")


def _print_reflection_findings(findings: List[Dict[str, Any]]) -> None:
    if not findings:
        print("[+] No reflected parameters found.")
        return

    print("\n========== Reflection Findings ==========\n")
    for r in findings:
        t = r.get("target", {}) or {}
        print("[!] Reflected parameter detected")
        print(f"    URL: {t.get('url','')}")
        print(f"    Method: {t.get('method','')}")
        print(f"    Parameter: {r.get('param','')}\n")
    print("=========================================\n")


def _print_ssti_engine_summary(engine_name: str, results: List[Dict[str, Any]]) -> None:
    if not results:
        print(f"[+] No {engine_name} SSTI results (no targets/params).")
        return

    print(f"\n========== Toasti SSTI Summary ({engine_name}) ==========\n")

    results_sorted = sorted(
        results,
        key=lambda r: (
            (r.get("target") or {}).get("url", ""),
            (r.get("target") or {}).get("method", ""),
            str(r.get("param", "")),
        )
    )

    vuln_count = 0
    for r in results_sorted:
        t = r.get("target", {}) or {}
        verdict = r.get("verdict", {}) or {}
        refl = (r.get("reflection_check") or {})

        url = t.get("url", "")
        method = t.get("method", "")
        param = r.get("param", "")

        reflected = (refl.get("reflected") is True)
        pass_count = int(verdict.get("pass_count", 0) or 0)
        probe_count = int(verdict.get("probe_count", 0) or 0)
        confidence = int(verdict.get("confidence", 0) or 0)
        vulnerable = (verdict.get("vulnerable") is True)

        if vulnerable:
            vuln_count += 1

        print(f"[+] Target: {url} ({method})")
        print(f"    Param: {param}")
        print(f"    Reflection: {'YES' if reflected else 'NO'}")
        print(f"    {engine_name} probes: {pass_count}/{probe_count} passed")
        print(f"    Confidence: {confidence}")
        print(f"    Verdict: {'VULNERABLE' if vulnerable else 'Not vulnerable'}\n")

    print(f"[+] Vulnerable findings: {vuln_count}/{len(results_sorted)}")
    print("===============================================\n")


def _print_osinj_summary_neat(results: List[Dict[str, Any]]) -> None:
    if not results:
        print("[+] No OS-injection results (no targets/params).")
        return

    print("\n========== Toasti OS Injection Summary ==========\n")

    results_sorted = sorted(
        results,
        key=lambda r: (
            (r.get("target") or {}).get("url", ""),
            (r.get("target") or {}).get("method", ""),
            str(r.get("param", "")),
        )
    )

    vuln_count = 0
    for r in results_sorted:
        t = r.get("target", {}) or {}
        verdict = r.get("verdict", {}) or {}

        url = t.get("url", "")
        method = t.get("method", "")
        param = r.get("param", "")

        pass_count = int(verdict.get("pass_count", 0) or 0)
        probe_count = int(verdict.get("probe_count", 0) or 0)
        confidence = int(verdict.get("confidence", 0) or 0)
        vulnerable = (verdict.get("vulnerable") is True)

        if vulnerable:
            vuln_count += 1

        print(f"[+] Target: {url} ({method})")
        print(f"    Param: {param}")
        print(f"    OS probes: {pass_count}/{probe_count} passed")
        print(f"    Confidence: {confidence}")
        print(f"    Verdict: {'VULNERABLE' if vulnerable else 'Not vulnerable'}\n")

    print(f"[+] Vulnerable findings: {vuln_count}/{len(results_sorted)}")
    print("===============================================\n")


def main() -> None:
    p = argparse.ArgumentParser(prog="toasti")

    p.add_argument("-u", "--url", required=True, help="Target start URL")
    p.add_argument("--depth", type=int, default=1, help="Crawl depth")
    p.add_argument("--max-pages", type=int, default=50, help="Max pages to crawl")

    p.add_argument("--header", nargs="*", help="Headers key=value")
    p.add_argument("--cookie", nargs="*", help="Cookies key=value")
    p.add_argument("--timeout", type=int, default=15)
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification")

    # Auth
    p.add_argument("--login-url", default="", help="Login page URL")
    p.add_argument("--user", default="", help="Username for login")
    p.add_argument("--pass", dest="password", default="", help="Password for login")
    p.add_argument("--user-field", default="", help="Override username field")
    p.add_argument("--pass-field", default="", help="Override password field")
    p.add_argument("--login-check-url", default="", help="Optional post-login check URL")

    # Engines
    p.add_argument("--reflect", action="store_true", help="Run reflection probe")
    p.add_argument("--ssti-jinja2", action="store_true", help="Run Jinja2 SSTI detection")
    p.add_argument("--ssti-twig", action="store_true", help="Run Twig SSTI detection (placeholders)")
    p.add_argument("--ssti-freemarker", action="store_true", help="Run FreeMarker SSTI detection (placeholders)")
    p.add_argument("--ssti-velocity", action="store_true", help="Run Velocity SSTI detection (placeholders)")
    p.add_argument("--ssti-mustache", action="store_true", help="Run Mustache/Handlebars SSTI detection (placeholders)")
    p.add_argument("--os-inject", action="store_true", help="Run OS command injection detection (scaffold)")

    # Visibility
    p.add_argument("--show-targets", action="store_true", help="Print all unique scan targets (injection points)")
    p.add_argument("--show-ssti-all", action="store_true", help="Print SSTI results for ALL tested params (neat summary)")
    p.add_argument("--show-os-all", action="store_true", help="Print OS-injection results for ALL tested params (neat summary)")

    # Output
    p.add_argument("--json-out", default="", help="Write JSON output to file")

    args = p.parse_args()

    if args.insecure:
        try:
            import urllib3
            from urllib3.exceptions import InsecureRequestWarning
            urllib3.disable_warnings(category=InsecureRequestWarning)
        except Exception:
            pass

    headers = _parse_kv_list(args.header)
    cookies = _parse_kv_list(args.cookie)

    client = HTTPClient(headers=headers, cookies=cookies, timeout=args.timeout, verify_tls=not args.insecure)

    print(f"[+] Starting Toasti against {args.url}")

    # Login (optional)
    if args.login_url:
        if not args.user or not args.password:
            print("[!] When using --login-url, you must provide --user and --pass")
            sys.exit(1)

        auth_res = authenticate_form(
            client=client,
            login_url=args.login_url,
            username=args.user,
            password=args.password,
            user_field=args.user_field or None,
            pass_field=args.pass_field or None,
            check_url=args.login_check_url or None,
            require_same_origin=True,
        )

        if auth_res.ok:
            print(f"[+] Auth OK: {auth_res.reason}")
        else:
            print(f"[!] Auth FAILED: {auth_res.reason}")
            return

    # Crawl
    print("[+] Crawling target.")
    crawl_result = crawl_site(
        client=client,
        start_url=args.url,
        depth=args.depth,
        max_pages=args.max_pages,
        same_host_only=True,
    )

    forms_index = crawl_result.get("forms_index", []) or []
    api_endpoints = crawl_result.get("api_endpoints", []) or []
    openapi_targets = crawl_result.get("openapi_targets", []) or []
    query_urls = crawl_result.get("query_urls", []) or []

    print(f"[+] Pages crawled: {crawl_result.get('pages_crawled', 0)}")
    print(f"[+] Forms discovered: {len(forms_index)}")
    print(f"[+] API endpoints discovered: {len(api_endpoints)}")
    print(f"[+] Query URLs discovered: {len(query_urls)}")

    targets = build_targets_from_forms_index(
        forms_index=forms_index,
        api_endpoints=api_endpoints,
        openapi_targets=openapi_targets,
        base_url=args.url,
        query_urls=query_urls,
    )

    print(f"[+] Total scan targets built: {len(targets)}")

    if args.show_targets:
        _print_targets(targets)

    out_blob: Dict[str, Any] = {
        "start_url": args.url,
        "crawl": crawl_result,
        "targets": [t.to_dict() for t in targets],
        "results": {}
    }

    if args.reflect:
        print("[+] Running reflection scan.")
        reflect_results = reflection_probe(client, targets)
        out_blob["results"]["reflection"] = reflect_results
        _print_reflection_findings(reflect_results)

    # SSTI engines
    if args.ssti_jinja2:
        print("[+] Running Jinja2 SSTI scan.")
        res = jinja2_ssti_scan(client, targets)
        out_blob["results"]["ssti_jinja2"] = res
        if args.show_ssti_all:
            _print_ssti_engine_summary("jinja2", res)
        else:
            vulns = [r for r in res if (r.get("verdict") or {}).get("vulnerable") is True]
            _print_ssti_engine_summary("jinja2", vulns) if vulns else print("[+] No Jinja2 SSTI vulnerabilities detected.")

    if args.ssti_twig:
        print("[+] Running Twig SSTI scan.")
        res = twig_ssti_scan(client, targets)
        out_blob["results"]["ssti_twig"] = res
        if args.show_ssti_all:
            _print_ssti_engine_summary("twig", res)
        else:
            vulns = [r for r in res if (r.get("verdict") or {}).get("vulnerable") is True]
            _print_ssti_engine_summary("twig", vulns) if vulns else print("[+] No Twig SSTI vulnerabilities detected.")

    if args.ssti_freemarker:
        print("[+] Running FreeMarker SSTI scan.")
        res = freemarker_ssti_scan(client, targets)
        out_blob["results"]["ssti_freemarker"] = res
        if args.show_ssti_all:
            _print_ssti_engine_summary("freemarker", res)
        else:
            vulns = [r for r in res if (r.get("verdict") or {}).get("vulnerable") is True]
            _print_ssti_engine_summary("freemarker", vulns) if vulns else print("[+] No FreeMarker SSTI vulnerabilities detected.")

    if args.ssti_velocity:
        print("[+] Running Velocity SSTI scan.")
        res = velocity_ssti_scan(client, targets)
        out_blob["results"]["ssti_velocity"] = res
        if args.show_ssti_all:
            _print_ssti_engine_summary("velocity", res)
        else:
            vulns = [r for r in res if (r.get("verdict") or {}).get("vulnerable") is True]
            _print_ssti_engine_summary("velocity", vulns) if vulns else print("[+] No Velocity SSTI vulnerabilities detected.")

    if args.ssti_mustache:
        print("[+] Running Mustache SSTI scan.")
        res = mustache_ssti_scan(client, targets)
        out_blob["results"]["ssti_mustache"] = res
        if args.show_ssti_all:
            _print_ssti_engine_summary("mustache", res)
        else:
            vulns = [r for r in res if (r.get("verdict") or {}).get("vulnerable") is True]
            _print_ssti_engine_summary("mustache", vulns) if vulns else print("[+] No Mustache SSTI vulnerabilities detected.")

    # OS injection scaffold
    if args.os_inject:
        print("[+] Running OS injection scan (scaffold).")
        os_res = os_injection_scan(client, targets)
        out_blob["results"]["os_injection"] = os_res
        if args.show_os_all:
            _print_osinj_summary_neat(os_res)
        else:
            vulns = [r for r in os_res if (r.get("verdict") or {}).get("vulnerable") is True]
            _print_osinj_summary_neat(vulns) if vulns else print("[+] No OS injection vulnerabilities detected.")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            f.write(json.dumps(out_blob, indent=2))
        print(f"[+] JSON written to {args.json_out}")

    print("[+] Scan complete.")


if __name__ == "__main__":
    main()
