import os


class ContextExtractor:
    """
    Extracts the local code context for an LLM to evaluate a vulnerability.
    Captures file imports and a strict +/- window of adjacent lines.
    """

    def __init__(self, window_size: int = 10) -> None:
        self.window_size = window_size

    def extract(self, file_path: str, target_line: int) -> str:
        """
        Reads the file and returns a formatted string with imports and the snippet.
        """
        if not os.path.exists(file_path):
            return "Error: File not found."

        with open(file_path, encoding="utf-8") as f:
            lines = f.readlines()

        if not lines:
            return "Error: Empty file."

        # 1. Extract imports
        imports: list[str] = [
            line.strip()
            for line in lines
            if line.startswith("import ") or line.startswith("from ")
        ]

        # 2. Calculate window (0-indexed)
        target_idx = target_line - 1
        start_idx = max(0, target_idx - self.window_size)
        end_idx = min(len(lines), target_idx + self.window_size + 1)

        snippet = lines[start_idx:end_idx]

        # 3. Format the final context string for the LLM
        context_parts: list[str] = []
        if imports:
            context_parts.append("IMPORTS:\n" + "\n".join(imports))

        context_parts.append(f"CODE SNIPPET (Lines {start_idx + 1}-{end_idx}):")
        context_parts.append("".join(snippet))

        return "\n\n".join(context_parts)
