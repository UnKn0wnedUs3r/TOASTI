def print_ssti_summary(results):
    print("\n========== Toasti SSTI Summary ==========\n")

    for r in results:
        target = r["target"]
        verdict = r["verdict"]

        url = target["url"]
        method = target["method"]
        param = r["param"]

        reflected = r["reflection_check"]["reflected"]
        eval_present = r["ssti_probe"]["eval_present"]
        confidence = verdict["confidence"]
        vulnerable = verdict["vulnerable"]

        print(f"[+] Target: {url} ({method})")
        print(f"    Param: {param}")
        print(f"    Reflection: {'YES' if reflected else 'NO'}")
        print(f"    Jinja2 evaluation: {'YES' if eval_present else 'NO'}")
        print(f"    Confidence: {confidence}")

        if vulnerable:
            print("    Verdict: \033[91mVULNERABLE\033[0m\n")
        else:
            print("    Verdict: \033[92mNot vulnerable\033[0m\n")

    print("========================================\n")
