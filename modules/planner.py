# modules/planner.py
import structlog
from concurrent.futures import ThreadPoolExecutor, as_completed

from safety.whitelist import is_whitelisted

log = structlog.get_logger("planner")


def full_analysis_multi(targets, max_workers=1):
    """
    Multi-target анализ.
    """
    # --- 1. фильтр whitelist ---
    safe = [t for t in targets if is_whitelisted(t)]
    skipped = [t for t in targets if t not in set(safe)]

    if skipped:
        log.warning("multi_skipped_not_whitelisted", skipped=skipped)
        print(f"[!] Пропущено (не в whitelist): {', '.join(skipped)}")

    if not safe:
        log.error("multi_no_valid_targets", input_count=len(targets))
        print("[!] Ни одной цели в whitelist — выход")
        return {}

    log.info("multi_started", n=len(safe), workers=max_workers)
    print(f"\n[*] Multi-target: {len(safe)} целей, workers={max_workers}\n")

    results: dict = {}

    # --- 2a. последовательный режим (по умолчанию) ---
    if max_workers <= 1:
        for t in safe:
            try:
                log.info("multi_target_started", target=t)
                results[t] = full_analysis(t, quiet=True)
                n_ports = len(results[t].get("ports", []))
                print(f"[+] {t}: ок, портов = {n_ports}")
                log.info("multi_target_done", target=t, ports=n_ports)
            except Exception as e:
                print(f"[!] {t}: ошибка — {e}")
                log.exception("multi_target_failed", target=t)
                results[t] = {"target": t, "error": str(e), "ports": []}

    # --- 2b. параллельный режим ---
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(full_analysis, t, quiet=True): t for t in safe}
            for fut in as_completed(futures):
                t = futures[fut]
                try:
                    results[t] = fut.result()
                    n_ports = len(results[t].get("ports", []))
                    print(f"[+] {t}: ок, портов = {n_ports}")
                    log.info("multi_target_done", target=t, ports=n_ports)
                except Exception as e:
                    print(f"[!] {t}: ошибка — {e}")
                    log.exception("multi_target_failed", target=t)
                    results[t] = {"target": t, "error": str(e), "ports": []}

    # --- 3. summary ---
    n_ok = sum(1 for r in results.values() if not r.get("error"))
    n_fail = len(results) - n_ok
    log.info(
        "multi_finished",
        total_input=len(targets),
        scanned=len(safe),
        skipped=len(skipped),
        ok=n_ok,
        failed=n_fail,
    )
    print(
        f"\n[*] Итог: {n_ok} ок, {n_fail} ошибок, "
        f"{len(skipped)} пропущено (не в whitelist)\n"
    )
    return results
