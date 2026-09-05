"""CWE-78: VULNERABLE — async function calls asyncio.create_subprocess_shell
with user-provided argument. The async pattern may evade simple AST walkers
that only look for subprocess module calls."""

import asyncio


async def run_health_check(host: str, timeout: int = 5) -> str | None:
    cmd = f"ping -c 1 -W {timeout} {host}"
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode == 0:
            return stdout.decode().strip()
        return None
    except OSError:
        return None


async def check_multiple_hosts(hosts: list[str]) -> dict[str, bool]:
    results = {}
    tasks = [run_health_check(h) for h in hosts]
    outputs = await asyncio.gather(*tasks, return_exceptions=True)
    for host, output in zip(hosts, outputs, strict=False):
        results[host] = output is not None and not isinstance(output, Exception)
    return results


if __name__ == "__main__":
    import sys

    targets = sys.argv[1:] or ["127.0.0.1"]
    print(asyncio.run(check_multiple_hosts(targets)))
