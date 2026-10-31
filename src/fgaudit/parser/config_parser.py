from __future__ import annotations

import logging
from typing import Iterator, Optional

from ..models import GLOBAL_VDOM, ROOT_VDOM, ConfigModel, ConfigObject
from .tokenizer import split_line

logger = logging.getLogger(__name__)

_VDOM_CONTAINER = "vdom"
_GLOBAL_CONTAINER = "global"
_CONTAINERS = (_VDOM_CONTAINER, _GLOBAL_CONTAINER)


def _unescaped_quote_count(line: str) -> int:
    count = 0
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\":
            i += 2
            continue
        if ch == '"':
            count += 1
        i += 1
    return count


def logical_lines(text: str) -> Iterator[tuple[int, str]]:
    buf: list[str] = []
    start_no = 0
    open_quotes = False
    for lineno, raw in enumerate(text.splitlines(), start=1):
        if not buf:
            start_no = lineno
        buf.append(raw)
        if _unescaped_quote_count(raw) % 2 == 1:
            open_quotes = not open_quotes
        if not open_quotes:
            yield start_no, "\n".join(buf)
            buf = []
    if buf:
        yield start_no, "\n".join(buf)


class _Frame:
    __slots__ = ("kind", "path", "objects", "body", "pushed_vdom", "is_vdom_edit")

    def __init__(self, kind: str, path: str, body: Optional[ConfigObject] = None):
        self.kind = kind
        self.path = path
        self.objects: list[ConfigObject] = []
        self.body = body
        self.pushed_vdom = False
        self.is_vdom_edit = False

    def is_container(self) -> bool:
        return self.is_vdom_edit or (self.kind == "config" and self.path in _CONTAINERS)


class FortiParser:
    def __init__(self) -> None:
        self.model = ConfigModel()
        self._stack: list[_Frame] = []
        self._vdom_stack: list[str] = []
        self._vdoms_seen: set[str] = set()

    def _cur_vdom(self) -> str:
        return self._vdom_stack[-1] if self._vdom_stack else ROOT_VDOM

    def _enclosing_body(self) -> Optional[ConfigObject]:
        for frame in reversed(self._stack):
            if frame.is_container():
                return None
            if frame.body is not None:
                return frame.body
        return None

    def _emit_config(self, frame: _Frame) -> None:
        if frame.objects:
            emitted = frame.objects
        elif frame.body and (frame.body.settings or frame.body.children):
            emitted = [frame.body]
        else:
            return
        parent = self._enclosing_body()
        if parent is not None:
            parent.children.setdefault(frame.path, []).extend(emitted)
        else:
            for obj in emitted:
                self.model.add(obj)

    def parse(self, text: str) -> ConfigModel:
        lineno = 0
        for lineno, line in logical_lines(text.lstrip("﻿")):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            head = stripped.split(None, 1)[0]
            if head == "config":
                self._open_config(stripped, lineno)
            elif head == "edit":
                self._open_edit(stripped, lineno)
            elif stripped == "next":
                self._close_edit()
            elif stripped == "end":
                self._close_config()
            elif head in ("set", "unset", "append"):
                self._handle_set(stripped)
        self._flush()
        self.model.vdoms = sorted(self._vdoms_seen) or [ROOT_VDOM]
        self.model.source_lines = lineno
        return self.model

    def _open_config(self, line: str, lineno: int) -> None:
        path = line[len("config "):].strip().strip('"')
        frame = _Frame("config", path)
        if path in _CONTAINERS:
            self.model.multi_vdom = True
        if path == _GLOBAL_CONTAINER:
            self._vdom_stack.append(GLOBAL_VDOM)
            frame.pushed_vdom = True
            self._vdoms_seen.add(GLOBAL_VDOM)
        elif path != _VDOM_CONTAINER:
            frame.body = ConfigObject(name="", section=path, vdom=self._cur_vdom(), line=lineno)
        self._stack.append(frame)

    def _open_edit(self, line: str, lineno: int) -> None:
        toks = split_line(line)
        ident = toks[1] if len(toks) > 1 else line[len("edit "):].strip().strip('"')
        parent = self._stack[-1] if self._stack else None
        frame = _Frame("edit", ident)

        if parent is not None and parent.kind == "config" and parent.path == _VDOM_CONTAINER:
            frame.is_vdom_edit = True
            frame.pushed_vdom = True
            self._vdom_stack.append(ident)
            self._vdoms_seen.add(ident)
            self._stack.append(frame)
            return

        section = parent.path if (parent and parent.kind == "config") else ""
        obj = ConfigObject(name=ident, section=section, vdom=self._cur_vdom(), line=lineno)
        frame.body = obj
        if parent is not None and parent.kind == "config":
            parent.objects.append(obj)
        self._stack.append(frame)

    def _close_edit(self) -> None:
        while self._stack:
            frame = self._stack.pop()
            if frame.kind == "config":
                self._emit_config(frame)
                if frame.pushed_vdom and self._vdom_stack:
                    self._vdom_stack.pop()
                continue
            if frame.pushed_vdom and self._vdom_stack:
                self._vdom_stack.pop()
            break

    def _close_config(self) -> None:
        while self._stack:
            frame = self._stack.pop()
            if frame.kind == "edit":
                if frame.pushed_vdom and self._vdom_stack:
                    self._vdom_stack.pop()
                continue
            self._emit_config(frame)
            if frame.pushed_vdom and self._vdom_stack:
                self._vdom_stack.pop()
            break

    def _handle_set(self, line: str) -> None:
        toks = split_line(line)
        if len(toks) < 2:
            return
        verb, key, values = toks[0], toks[1], toks[2:]
        for frame in reversed(self._stack):
            if frame.is_container():
                return
            if frame.body is not None:
                settings = frame.body.settings
                if verb == "unset":
                    settings[key] = []
                elif verb == "append":
                    settings.setdefault(key, []).extend(values)
                else:
                    settings[key] = values
                return

    def _flush(self) -> None:
        while self._stack:
            frame = self._stack.pop()
            if frame.kind == "config":
                self._emit_config(frame)
            if frame.pushed_vdom and self._vdom_stack:
                self._vdom_stack.pop()


def parse_config(text: str) -> ConfigModel:
    return FortiParser().parse(text)
