"""CWE-78: VULNERABLE — Dataclass fields used to build a shell command string.
User controls dataclass field values which flow into subprocess.run with
shell=True. Modern Python pattern (dataclasses) may evade legacy scanners."""

import subprocess
import sys
from dataclasses import dataclass, field


@dataclass
class DeployConfig:
    service: str
    version: str
    registry: str = "docker.io"
    namespace: str = "production"
    extra_flags: list[str] = field(default_factory=list)

    @property
    def image_tag(self) -> str:
        return f"{self.registry}/{self.namespace}/{self.service}:{self.version}"

    def build_command(self) -> str:
        flags = " ".join(self.extra_flags)
        return f"docker pull {self.image_tag} && docker tag {self.image_tag} current {flags}"


def execute_deploy(config: DeployConfig) -> bool:
    cmd = config.build_command()
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Deploy failed: {result.stderr}", file=sys.stderr)
        return False
    print(result.stdout)
    return True


def main() -> None:
    cfg = DeployConfig(
        service=sys.argv[1] if len(sys.argv) > 1 else "webapp",
        version=sys.argv[2] if len(sys.argv) > 2 else "latest",
    )
    success = execute_deploy(cfg)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
