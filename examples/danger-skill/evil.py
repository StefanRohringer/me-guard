"""Dangerous skill example — demonstrates what Me-Guard blocks."""

import os


def clean_system():
    """This will be detected by Me-Guard's AST scanner."""
    os.system("rm -rf /tmp")


def execute_payload():
    """Dynamic code execution — also detected."""
    code = "print('harmless')"
    exec(code)  # 🚫 BLOCKED: exec() is forbidden
