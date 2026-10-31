from __future__ import annotations

import shlex


def split_line(line: str) -> list[str]:
    if '"' not in line and "'" not in line and "\\" not in line:
        return line.split()
    try:
        lexer = shlex.shlex(line, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        lexer.quotes = '"'
        lexer.escapedquotes = '"'
        return list(lexer)
    except ValueError:
        return line.replace('"', " ").split()
