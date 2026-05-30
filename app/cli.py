import argparse
import asyncio
import os
import sys

from app.core.cache import AnalysisCache
from app.llm.client import OllamaClient
from app.scanner import SecurityScanner


async def scan_file(file_path: str) -> None:
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)

    print(f"\n[*] Starting ASTra Security Scan on: {file_path}")

    # Initialize core components
    scanner = SecurityScanner()
    cache = AnalysisCache()
    llm_client = OllamaClient()

    # Static Analysis Phase (AST)
    print("[*] Phase 1: Static AST parsing...")
    static_results = scanner.scan_file(file_path)

    if not static_results:
        print("[+] No potential vulnerabilities found. File is clean.")
        return

    print(f"[!] Found {len(static_results)} potential vulnerabilities.")

    # Semantic Validation Phase (LLM + Cache)
    print("[*] Phase 2: Semantic analysis via LLM...\n")

    for finding, context in static_results:
        print(f"--- Analyzing {finding.cwe_id} at line {finding.line_number} ---")

        # Check cryptographic cache first
        llm_response = cache.get(context)

        if llm_response:
            print("[+] CACHE HIT: Retrieved previous analysis.")
        else:
            print("[-] CACHE MISS: Requesting analysis from Ollama...")
            llm_response = await llm_client.analyze_vulnerability(
                finding.cwe_id, context
            )

            if llm_response:
                cache.set(context, llm_response)
            else:
                print("[!] LLM failed to return a valid response. Skipping.\n")
                continue

        # Update finding with LLM insights
        finding.confidence = llm_response.confidence
        finding.exploit_path = llm_response.exploit_path
        finding.is_false_positive = not llm_response.is_exploitable

        # Print final verdict
        if finding.is_false_positive:
            print(f"[OK] False Positive Confirmed (Conf: {finding.confidence})")
        else:
            print(f"[VULN] Confirmed Vulnerability! (Conf: {finding.confidence})")
            print(f"       Path: {finding.exploit_path}")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ASTra - Hybrid AST + LLM Security Auditor"
    )
    parser.add_argument("file", help="Path to the Python file to analyze")

    args = parser.parse_args()

    # Execute the async application
    asyncio.run(scan_file(args.file))


if __name__ == "__main__":
    main()
