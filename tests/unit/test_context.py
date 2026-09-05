import os

from app.ingestion.context import ContextExtractor


def test_context_extractor_retrieves_imports_and_window(tmp_path: str) -> None:
    """Test that the extractor properly gets imports and limits the window."""

    # Create a temporary fake python file for testing
    test_file = os.path.join(tmp_path, "fake_code.py")
    source_code = [
        "import os\n",
        "from sys import exit\n",
        "\n",
        "def safe_func():\n",
        "    pass\n",
        "\n",
        "def vulnerable_func(user_input):\n",
        "    os.system(user_input)\n",  # Target line: 8
        "\n",
        "def another_func():\n",
        "    return True\n",
    ]

    with open(test_file, "w", encoding="utf-8") as f:
        f.writelines(source_code)

    # Extract context with a very small window (+/- 1 line) for testing
    extractor = ContextExtractor(window_size=1)
    context = extractor.extract(file_path=test_file, target_line=8)

    assert "IMPORTS:" in context
    assert "import os" in context
    assert "CODE SNIPPET (Lines 7-9):" in context
    assert "def vulnerable_func" in context
    assert "another_func" not in context  # Should be outside the +/- 1 window
