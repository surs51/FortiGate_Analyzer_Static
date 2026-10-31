from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Iterator, Optional

GLOBAL_VDOM = "global"
ROOT_VDOM = "root"


@dataclass(slots=True)
class ConfigObject:
    name: str
    section: str
    vdom: str
    line: int = 0
    settings: dict[str, list[str]] = field(default_factory=dict)
    children: dict[str, list["ConfigObject"]] = field(default_factory=dict)

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        vals = self.settings.get(key)
        return vals[0] if vals else default

    def get_list(self, key: str) -> list[str]:
        return self.settings.get(key, [])

    def text(self, key: str, default: str = "") -> str:
        vals = self.settings.get(key)
        return " ".join(vals) if vals else default

    def lower(self, key: str, default: str = "") -> str:
        return (self.get(key) or default).lower()

    def flag(self, key: str, default: bool) -> bool:
        val = self.get(key)
        if val is None:
            return default
        return val.lower() == "enable"

    def is_set(self, key: str) -> bool:
        return key in self.settings

    def has_value(self, key: str, value: str) -> bool:
        return any(v.lower() == value.lower() for v in self.settings.get(key, []))

    def child(self, subsection: str) -> list["ConfigObject"]:
        return self.children.get(subsection, [])

    def child_singleton(self, subsection: str) -> Optional["ConfigObject"]:
        objs = self.children.get(subsection)
        return objs[0] if objs else None

    def evidence_line(self) -> str:
        where = f"line {self.line}" if self.line else "line ?"
        if self.name:
            return f"config {self.section} / edit {self.name} ({where})"
        return f"config {self.section} ({where})"


@dataclass(slots=True)
class ConfigModel:
    vdoms: list[str] = field(default_factory=lambda: [ROOT_VDOM])
    _sections: dict[tuple[str, str], list[ConfigObject]] = field(default_factory=dict)
    source_lines: int = 0
    multi_vdom: bool = False

    def add(self, obj: ConfigObject) -> None:
        self._sections.setdefault((obj.vdom, obj.section), []).append(obj)

    def objects(self, section: str, vdom: Optional[str] = None) -> list[ConfigObject]:
        if vdom is None:
            out: list[ConfigObject] = []
            for (_vd, sec), objs in self._sections.items():
                if sec == section:
                    out.extend(objs)
            return out
        out = list(self._sections.get((vdom, section), []))
        if vdom != GLOBAL_VDOM:
            out.extend(self._sections.get((GLOBAL_VDOM, section), []))
        return out

    def local_objects(self, section: str, vdom: str) -> list[ConfigObject]:
        return list(self._sections.get((vdom, section), []))

    def singleton(self, section: str, vdom: str = ROOT_VDOM) -> Optional[ConfigObject]:
        objs = self._sections.get((vdom, section))
        if objs:
            return objs[0]
        objs = self._sections.get((GLOBAL_VDOM, section))
        return objs[0] if objs else None

    def first(self, section: str) -> Optional[ConfigObject]:
        for obj in self.all_singletons(section):
            return obj
        return None

    def all_singletons(self, section: str) -> Iterator[ConfigObject]:
        for (_vd, sec), objs in self._sections.items():
            if sec == section:
                yield from objs

    def sections_present(self) -> set[str]:
        return {sec for (_vd, sec) in self._sections}

    def iter_all(self) -> Iterable[ConfigObject]:
        for objs in self._sections.values():
            yield from objs

    def count(self, section: str) -> int:
        return sum(
            len(objs) for (_vd, sec), objs in self._sections.items() if sec == section
        )

    @property
    def policy_vdoms(self) -> list[str]:
        return [v for v in self.vdoms if v != GLOBAL_VDOM] or [ROOT_VDOM]
