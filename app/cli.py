import argparse
import asyncio
import os
import sys

from app.core.cache import AnalysisCache
from app.core.scoring import ScoringEngine
from app.llm.client import OllamaClient
from app.logging_config import configure_logging
from app.scanner import SecurityScanner

# Initialize logging configuration
configure_logging()


async def scan_file(file_path: str) -> None:
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)

    print(f"\n[*] Starting ASTra Security Scan on: {file_path}")

    # Initialize core components
    scanner = SecurityScanner()
    cache = AnalysisCache()
    llm_client = OllamaClient()
    scoring_engine = ScoringEngine()

    # Static Analysis Phase (AST)
    print("[*] Phase 1: Static AST parsing...")
    static_results = scanner.scan_file(file_path)

    if not static_results:
        print("[+] No potential vulnerabilities found. File is clean.")
        return

    print(f"[!] Found {len(static_results)} potential vulnerabilities.")

    # Semantic Validation Phase (LLM + Cache)
    print("[*] Phase 2: Semantic analysis via LLM...\n")

    for finding in static_results:
        # Extract the code context that the AST parser has already isolated natively
        context = finding.code_snippet

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
            print(f"[OK] Filtered! (Score: {final_score} < 0.65)")
            print(f"     Reason: {llm_response.exploit_path}")
        else:
            print(f"[VULN] Confirmed Vulnerability! (Score: {final_score} >= 0.65)")
            print(f"       Path: {llm_response.exploit_path}")
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
