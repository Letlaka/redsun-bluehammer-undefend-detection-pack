#!/usr/bin/env python3
"""Lightweight repository validation for detection-pack pull requests."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTION_DIRS = ("RedSun", "BlueHammer", "UnDefend")
REQUIRED_KQL_HEADER = (
    "// SPDX-License-Identifier: Apache-2.0",
    "// Copyright 2026 Letlaka",
    "// AI-generated detection content. Review, test, tune, and verify before production use.",
)


def add_error(errors: list[str], path: Path, message: str) -> None:
    errors.append(f"{path.relative_to(ROOT)}: {message}")


def validate_balanced_delimiters(path: Path, text: str, errors: list[str]) -> None:
    opening = "([{"
    closing = {")": "(", "]": "[", "}": "{"}
    stack: list[tuple[str, int, int]] = []
    line = 1
    column = 0
    index = 0
    string_mode: str | None = None
    in_block_comment = False

    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        column += 1

        if char == "\n":
            line += 1
            column = 0
            index += 1
            continue

        if in_block_comment:
            if char == "*" and next_char == "/":
                in_block_comment = False
                index += 2
                column += 1
                continue
            index += 1
            continue

        if string_mode:
            if string_mode == "verbatim":
                if char == '"' and next_char == '"':
                    index += 2
                    column += 1
                    continue
                if char == '"':
                    string_mode = None
            elif char == "\\":
                index += 2
                column += 1
                continue
            elif char == string_mode:
                string_mode = None
            index += 1
            continue

        if char == "/" and next_char == "/":
            newline_index = text.find("\n", index)
            if newline_index == -1:
                break
            index = newline_index
            continue

        if char == "/" and next_char == "*":
            in_block_comment = True
            index += 2
            column += 1
            continue

        if char == "@" and next_char == '"':
            string_mode = "verbatim"
            index += 2
            column += 1
            continue

        if char in ('"', "'"):
            string_mode = char
            index += 1
            continue

        if char in opening:
            stack.append((char, line, column))
        elif char in closing:
            if not stack or stack[-1][0] != closing[char]:
                add_error(errors, path, f"unmatched `{char}` at line {line}, column {column}")
                return
            stack.pop()

        index += 1

    if string_mode:
        add_error(errors, path, f"unterminated {string_mode} string")
    if in_block_comment:
        add_error(errors, path, "unterminated block comment")
    if stack:
        char, start_line, start_column = stack[-1]
        add_error(errors, path, f"unclosed `{char}` from line {start_line}, column {start_column}")


def validate_kql_file(path: Path, errors: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()

    if tuple(lines[:3]) != REQUIRED_KQL_HEADER:
        add_error(errors, path, "missing required SPDX, copyright, or AI-generated-content header")

    if "let Lookback =" not in text:
        add_error(errors, path, "missing `let Lookback =` declaration")

    validate_balanced_delimiters(path, text, errors)


def validate_detection_dir(directory: Path, errors: list[str]) -> None:
    if not directory.is_dir():
        add_error(errors, directory, "missing detection directory")
        return

    readme = directory / "README.md"
    if not readme.is_file():
        add_error(errors, readme, "missing package README")

    kql_files = sorted(directory.glob("*.kql"))
    if not kql_files:
        add_error(errors, directory, "no KQL files found")
        return

    numbers: list[int] = []
    for file_path in kql_files:
        match = re.fullmatch(r"(\d{2})_.+\.kql", file_path.name)
        if not match:
            add_error(errors, file_path, "KQL filename must start with a two-digit sequence number")
            continue
        numbers.append(int(match.group(1)))
        validate_kql_file(file_path, errors)

    expected_numbers = list(range(1, len(kql_files) + 1))
    if numbers != expected_numbers:
        add_error(
            errors,
            directory,
            f"KQL numbering must be contiguous from 01; found {numbers}, expected {expected_numbers}",
        )

    first_file = kql_files[0].name
    if not re.fullmatch(r"01_.+_full_attack_chain\.kql", first_file):
        add_error(errors, kql_files[0], "first query must be the full attack-chain query")


def main() -> int:
    errors: list[str] = []

    for directory_name in DETECTION_DIRS:
        validate_detection_dir(ROOT / directory_name, errors)

    if errors:
        print("Repository validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    print("Repository validation passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
