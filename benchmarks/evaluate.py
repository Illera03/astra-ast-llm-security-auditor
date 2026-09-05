import asyncio
from pathlib import Path

import yaml
from tqdm import tqdm

from benchmarks.exporter import export_csv, export_json, export_table
from benchmarks.metrics import group_and_calculate
from benchmarks.runners import bandit, semgrep
from benchmarks.runners.astra import evaluate_file as astra_evaluate_file
from benchmarks.schemas import DatasetEntry, EvaluationResult


def load_manifest(manifest_path: str) -> list[DatasetEntry]:
    raw = yaml.safe_load(Path(manifest_path).read_text())
    return [DatasetEntry(**entry) for entry in raw]


async def run_astra(
    entries: list[DatasetEntry],
    datasets_dir: str,
    concurrency: int,
) -> list[EvaluationResult]:
    sem = asyncio.Semaphore(concurrency)
    results: list[EvaluationResult] = []

    async def _eval(entry: DatasetEntry) -> EvaluationResult:
        async with sem:
            return await astra_evaluate_file(entry, datasets_dir)

    tasks = [_eval(e) for e in entries]

    for coro in tqdm(
        asyncio.as_completed(tasks),
        total=len(tasks),
        desc="ASTra",
        unit="file",
    ):
        result = await coro
        results.append(result)

    return results


async def run_benchmark(
    manifest_path: str,
    concurrency: int = 10,
    output_dir: str = "benchmarks/results",
    formats: str = "table",
    tools: str = "astra,bandit,semgrep",
) -> None:
    entries = load_manifest(manifest_path)
    datasets_dir = str(Path(manifest_path).parent)

    tool_list = [t.strip() for t in tools.split(",")]
    all_results: list[EvaluationResult] = []

    if "astra" in tool_list:
        print(f"\n[*] Running ASTra on {len(entries)} files...")
        astra_results = await run_astra(entries, datasets_dir, concurrency)
        all_results.extend(astra_results)

    if "bandit" in tool_list:
        print(f"\n[*] Running Bandit on {datasets_dir}...")
        bandit_results = bandit.evaluate_entries(entries, datasets_dir)
        all_results.extend(bandit_results)

    if "semgrep" in tool_list:
        print(f"\n[*] Running Semgrep on {datasets_dir}...")
        semgrep_results = semgrep.evaluate_entries(entries, datasets_dir)
        all_results.extend(semgrep_results)

    summaries = group_and_calculate(all_results)

    format_list = [f.strip() for f in formats.split(",")]

    if "table" in format_list:
        print("\n" + export_table(summaries))

    if "csv" in format_list:
        csv_path = f"{output_dir}/benchmark_results.csv"
        export_csv(summaries, csv_path)
        print(f"\n[*] CSV exported to: {csv_path}")

    if "json" in format_list:
        json_path = f"{output_dir}/benchmark_results.json"
        export_json(all_results, summaries, json_path)
        print(f"\n[*] JSON exported to: {json_path}")
