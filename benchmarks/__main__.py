import argparse
import asyncio

from benchmarks.evaluate import run_benchmark


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ASTra Benchmark Evaluator"
    )
    parser.add_argument(
        "--manifest",
        default="datasets/manifest.yaml",
        help="Path to the dataset manifest (default: datasets/manifest.yaml)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=10,
        help="Max concurrent ASTra LLM calls (default: 10)",
    )
    parser.add_argument(
        "--output-dir",
        default="benchmarks/results",
        help="Directory for output files (default: benchmarks/results)",
    )
    parser.add_argument(
        "--format",
        default="table",
        help="Output formats, comma-separated: table,csv,json (default: table)",
    )
    parser.add_argument(
        "--tools",
        default="astra,bandit,semgrep",
        help="Tools to evaluate, comma-separated (default: astra,bandit,semgrep)",
    )

    args = parser.parse_args()

    asyncio.run(run_benchmark(
        manifest_path=args.manifest,
        concurrency=args.concurrency,
        output_dir=args.output_dir,
        formats=args.format,
        tools=args.tools,
    ))


if __name__ == "__main__":
    main()
