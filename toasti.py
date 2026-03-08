from __future__ import annotations

import argparse
import sys
import os

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
# NEW FEATURE: OUTPUT TO TXT FILE (SAFE VERSION)
# ============================================================

class TeeOutput:

    def __init__(self, filename):

        os.makedirs("reports", exist_ok=True)

        self.path = os.path.join("reports", filename)

        self.file = open(self.path, "w", encoding="utf-8")

        self.original_stdout = sys.stdout


    def write(self, data):

        self.original_stdout.write(data)
        self.file.write(data)


    def flush(self):

        try:

            self.original_stdout.flush()
            self.file.flush()

        except:

            pass


    def close(self):

        try:

            self.file.close()

        except:

            pass


# ============================================================
# SSTI & OS INJECTION DESCRIPTION DATABASE
# ============================================================

SSTI_INFO = {

    "jinja2": {
        "name": "Jinja2",
        "description":
        "Jinja2 Server-Side Template Injection (SSTI) occurs when user input is "
        "embedded directly into a Jinja2 template and interpreted by the template "
        "engine.\n\n"
        "If the application fails to properly sanitize or escape the input, "
        "attackers may inject template expressions such as {{...}} which are "
        "executed during template rendering. Because Jinja2 integrates closely "
        "with Python, attackers may gain access to internal objects, application "
        "data, or system resources.",

        "impact":
        "Successful exploitation may allow attackers to execute arbitrary Python "
        "code on the server.\n\n"
        "Attackers could read sensitive files, access environment variables, "
        "extract credentials, or manipulate application logic. In severe cases "
        "this vulnerability can result in full system compromise.",

        "fix":
        "Avoid rendering raw user input directly inside templates.\n\n"
        "Implement strict input validation and escaping mechanisms, and ensure "
        "that template environments restrict access to sensitive objects or "
        "functions."
    },

    "twig": {
        "name": "Twig",
        "description":
        "Twig Server-Side Template Injection occurs when untrusted user input "
        "is embedded into Twig templates and evaluated by the template engine.\n\n"
        "Attackers may inject Twig expressions using {{...}} or {%...%} syntax, "
        "which causes unintended logic to execute during template rendering.",

        "impact":
        "Exploitation may allow attackers to execute arbitrary template logic, "
        "leading to data exposure or application manipulation.\n\n"
        "In insecure configurations attackers may gain access to underlying PHP "
        "functions or system resources.",

        "fix":
        "Do not insert untrusted user input directly into Twig templates.\n\n"
        "Apply strict input validation and consider enabling Twig sandbox mode "
        "to restrict dangerous functionality."
    },

    "freemarker": {
        "name": "FreeMarker",
        "description":
        "FreeMarker Server-Side Template Injection (SSTI) occurs when user input "
        "is inserted directly into a FreeMarker template and evaluated by the "
        "template engine.\n\n"
        "If input is not properly sanitized, attackers can inject FreeMarker "
        "expressions such as ${...} that the server processes during template "
        "rendering. This allows malicious template code to execute within the "
        "server environment and potentially access system objects, files, or "
        "execute commands.",

        "impact":
        "Successful exploitation can allow attackers to execute arbitrary code "
        "on the server, read sensitive files, access environment variables, or "
        "manipulate application data.\n\n"
        "In severe cases this may lead to remote command execution or full "
        "server compromise.",

        "fix":
        "Applications should avoid rendering user-controlled input directly "
        "inside FreeMarker templates.\n\n"
        "Input should be validated and escaped before processing. Developers "
        "should also disable dangerous FreeMarker features such as unrestricted "
        "access to Java classes and ensure secure template configurations."
    },

    "velocity": {
        "name": "Velocity",
        "description":
        "Velocity Server-Side Template Injection occurs when untrusted user "
        "input is embedded into Apache Velocity templates and interpreted by "
        "the template engine.\n\n"
        "Attackers may inject Velocity expressions such as $variable or "
        "#set directives which execute during template rendering.",

        "impact":
        "Successful exploitation may allow attackers to access internal "
        "application objects, execute arbitrary Java methods, or retrieve "
        "sensitive information.\n\n"
        "Depending on the environment configuration this could lead to remote "
        "code execution or full server compromise.",

        "fix":
        "Avoid embedding raw user input into Velocity templates.\n\n"
        "Restrict the objects exposed to the template engine and implement "
        "strict input validation to ensure only safe data is processed."
    },

    "mustache": {
        "name": "Mustache",
        "description":
        "Mustache template injection occurs when user-controlled input is "
        "inserted into Mustache templates without proper validation.\n\n"
        "Although Mustache is designed as a logic-less template engine, "
        "improper application implementation may still allow attackers to "
        "manipulate template variables or expose unintended application data.",

        "impact":
        "Attackers may exploit this issue to expose sensitive application data "
        "or manipulate rendered output.\n\n"
        "While the risk is typically lower compared to other template engines, "
        "insecure implementations may still lead to information disclosure.",

        "fix":
        "Ensure all user input is validated and properly escaped before being "
        "rendered in templates.\n\n"
        "Avoid exposing sensitive application objects or internal data within "
        "template contexts."
    },

    "os injection": {
        "name": "OS Command Injection",
        "description":
        "OS Command Injection occurs when user-supplied input is passed "
        "directly into system command execution functions without proper "
        "validation or sanitization.\n\n"
        "Applications that execute commands using functions such as system(), "
        "exec(), or subprocess may allow attackers to inject additional "
        "commands using operators like ;, &&, or |.",

        "impact":
        "Successful exploitation allows attackers to execute arbitrary "
        "operating system commands on the server.\n\n"
        "This may lead to data exfiltration, privilege escalation, service "
        "disruption, or full system compromise.",

        "fix":
        "Avoid executing system commands with unsanitized user input.\n\n"
        "Use safe APIs or parameterized execution methods instead of shell "
        "commands and implement strict input validation."
    }

}


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

        result = "Reflected" if r.get("reflected") else "Not Reflected"

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

    info = SSTI_INFO.get(name.lower())

    vulnerable = []
    not_vulnerable = []

    for r in results:

        if r["verdict"]["vulnerable"]:

            vulnerable.append(r)

        else:

            not_vulnerable.append(r)

    total = len(results)

    for r in vulnerable:

        url = r["target"]["url"]
        param = r["param"]

        print(f"Target: {url}")
        print(f"Parameter: {param}")
        print("Result: VULNERABLE")

        if info:

            print()
            print(f"Engine: {info['name']}")

        print()
        print("----------------------------------------")

    if vulnerable and info:

        print("\nDescription:\n")
        print(info["description"])

        print("\nImpact:\n")
        print(info["impact"])

        print("\nRecommendation:\n")
        print(info["fix"])

        print("\n----------------------------------------")

    print(f"VULNERABLE: {len(vulnerable)} / {total}\n")

    for r in not_vulnerable:

        url = r["target"]["url"]
        param = r["param"]

        print(f"Target: {url}")
        print(f"Parameter: {param}")
        print("Result: Not Vulnerable")
        print()

    print(f"NOT VULNERABLE: {len(not_vulnerable)} / {total}\n")


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

    # NEW OUTPUT ARGUMENT
    parser.add_argument("--output", help="Save output to reports folder")

    parser.add_argument("--show-targets", action="store_true")

    parser.add_argument("--reflect", action="store_true")

    parser.add_argument("--ssti-jinja2", action="store_true")
    parser.add_argument("--ssti-twig", action="store_true")
    parser.add_argument("--ssti-freemarker", action="store_true")
    parser.add_argument("--ssti-velocity", action="store_true")
    parser.add_argument("--ssti-mustache", action="store_true")

    parser.add_argument("--os-inject", action="store_true")

    args = parser.parse_args()


    tee = None

    if args.output:

        tee = TeeOutput(args.output)
        sys.stdout = tee


    print(f"[+] Starting Toasti against {args.url}")

    client = HTTPClient()


    # LOGIN

    if args.login_url:

        print("[+] Attempting login...")

        ok = perform_login(
            client,
            args.login_url,
            args.user,
            args.password
        )

        if ok:

            print("[+] Login success")

        else:

            print("[!] Login failed")
            sys.exit(1)


    print("[+] Crawling target")

    crawl = crawl_site(
        client,
        args.url,
        depth=args.depth
    )


    targets = build_targets_from_forms_index(
        forms_index=crawl.get("forms_index"),
        api_endpoints=crawl.get("api_endpoints"),
        openapi_targets=crawl.get("openapi_targets"),
        base_url=args.url,
        query_urls=crawl.get("query_urls")
    )


    print(f"[+] Total targets: {len(targets)}")


    if args.show_targets:

        print_targets(targets)


    if args.reflect:

        results = run_with_progress(
            "Reflection",
            reflection_probe,
            client,
            targets
        )

        print_reflection(results)


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


    if tee:

        sys.stdout = tee.original_stdout
        tee.close()

        print(f"\n[+] Report saved to reports/{args.output}")


# ============================================================

if __name__ == "__main__":

    main()
