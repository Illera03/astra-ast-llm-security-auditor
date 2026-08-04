import argparse
import asyncio
import json
import logging
import os
import sys

from app.core.cache import AnalysisCache
from app.core.scoring import ScoringEngine
from app.llm.client import OllamaClient
from app.logging_config import configure_logging
from app.scanner import SecurityScanner

# Initialize logging configuration
logging.getLogger("httpx").setLevel(logging.WARNING)
configure_logging()


async def scan_file(
    file_path: str, output_format: str, output_file: str | None
) -> None:
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.", file=sys.stderr)
        sys.exit(1)

    # Helper function: only prints if we're NOT outputting pure JSON to console
    def ui_print(msg: str = ""):
        if output_format == "console":
            print(msg)

    ui_print(f"\n[*] Starting ASTra Security Scan on: {file_path}")

    # Initialize core components
    scanner = SecurityScanner()
    cache = AnalysisCache()
    llm_client = OllamaClient()
    scoring_engine = ScoringEngine()

    # Static Analysis Phase (AST)
    ui_print("[*] Phase 1: Static AST parsing...")
    static_results = scanner.scan_file(file_path)

    if not static_results:
        ui_print("[+] No potential vulnerabilities found. File is clean.")
        return

    ui_print(f"[!] Found {len(static_results)} potential vulnerabilities.")

    # Semantic Validation Phase (LLM + Cache)
    ui_print("[*] Phase 2: Semantic analysis via LLM...\n")

    # List to accumulate confirmed vulnerabilities for report generation
    confirmed_vulnerabilities = []

    for finding in static_results:
        # Extract the code context that the AST parser has already isolated natively
        context = finding.code_snippet

        ui_print(f"--- Analyzing {finding.cwe_id} at line {finding.line_number} ---")

        # Check cryptographic cache first
        llm_response = cache.get(context)

        if llm_response:
            ui_print("[+] CACHE HIT: Retrieved previous analysis.")
        else:
            ui_print("[-] CACHE MISS: Requesting analysis from Ollama...")
            llm_response = await llm_client.analyze_vulnerability(
                finding.cwe_id, context
            )

            if llm_response:
                cache.set(context, llm_response)
            else:
                ui_print("[!] LLM failed to return a valid response. Skipping.\n")
                continue

        # Transform LLM confidence into a Risk Score
        # (If LLM says NOT exploitable with 0.9 confidence, the risk is 0.1)
        llm_risk = (
            llm_response.confidence
            if llm_response.is_exploitable
            else (1.0 - llm_response.confidence)
        )

        # Calculate hybrid final score using pre-calculated AST metrics
        final_score, is_critical = scoring_engine.evaluate(
            finding=finding, llm_risk_score=llm_risk
        )

        # Print final verdict
        if not is_critical:
            ui_print(f"[OK] Filtered! (Score: {final_score} < 0.65)")
            ui_print(f"     Reason: {llm_response.exploit_path}")
        else:
            ui_print(f"[VULN] Confirmed Vulnerability! (Score: {final_score} >= 0.65)")
            ui_print(f"       Path: {llm_response.exploit_path}")

            # Accumulate confirmed vulnerability for report generation
            confirmed_vulnerabilities.append(
                {
                    "cwe_id": finding.cwe_id,
                    "line_number": finding.line_number,
                    "severity": finding.severity.value
                    if hasattr(finding.severity, "value")
                    else str(finding.severity),
                    "final_score": final_score,
                    "exploit_path": llm_response.exploit_path,
                    "code_snippet": context,
                }
            )
        ui_print()

    # Final phase: Report Export
    if output_format == "json":
        report_data = {
            "scanned_file": file_path,
            "total_vulnerabilities_found": len(confirmed_vulnerabilities),
            "findings": confirmed_vulnerabilities,
        }

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=4)
            ui_print(f"[*] Report successfully exported to: {output_file}")
        else:
            # Output pure JSON (useful for piping with commands like `| jq` in the terminal)
            print(json.dumps(report_data, indent=4))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ASTra - Hybrid AST + LLM Security Auditor"
    )
    parser.add_argument("file", help="Path to the Python file to analyze")

    # Optional argument for output format
    parser.add_argument(
        "--format",
        choices=["console", "json"],
        default="console",
        help="Output format (default: console)",
    )

    # Optional argument for output file path
    parser.add_argument(
        "--output", "-o", help="Path to save the generated report (e.g., report.json)"
    )

    args = parser.parse_args()

    # Execute the async application
    asyncio.run(scan_file(args.file, args.format, args.output))


if __name__ == "__main__":
    main()
