"""Banner pattern matching using Aho-Corasick and Naive baseline algorithms.

Algorithmic Contributions:
- Aho-Corasick multi-pattern string matching constructed from scratch.
  - Trie structure with failure links and dictionary/output links.
  - Construction complexity: O(P) where P is the sum of pattern lengths.
  - Search complexity: O(L + Z) where L is text length and Z is match count.
- Naive matcher baseline:
  - Pattern-by-pattern linear scanning.
  - Baseline complexity: O(K * L) where K is pattern count.
- Version extraction heuristics decoupled from product detection.
"""

from __future__ import annotations

import collections
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass(frozen=True)
class Signature:
    """Service banner signature specification."""
    id: str
    pattern: str
    product: str
    protocol: str
    category: str = "Unknown"


@dataclass(frozen=True)
class Match:
    """An identified pattern occurrence within inspected text."""
    pattern_id: str
    pattern: str
    product: str
    protocol: str
    start_pos: int
    end_pos: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "pattern": self.pattern,
            "product": self.product,
            "protocol": self.protocol,
            "start_pos": self.start_pos,
            "end_pos": self.end_pos,
        }


class TrieNode:
    """A single state in the Aho-Corasick automaton."""

    __slots__ = ("children", "fail", "output")

    def __init__(self) -> None:
        self.children: dict[str, TrieNode] = {}
        self.fail: Optional[TrieNode] = None
        self.output: list[Signature] = []


class AhoCorasick:
    """Aho-Corasick automaton for simultaneous multi-pattern matching.

    Algorithmic details:
    1. Preprocessing (Trie Construction):
       Each pattern of length m_k is inserted character-by-character.
       Total time: O(P) where P = sum(len(p_k)).

    2. Failure Link Construction (BFS Traversal):
       Computes fallback transitions for mismatched characters using
       longest proper suffix matching.
       Merges output sets across failure links (dictionary links).
       Total time: O(P * |alphabet|), bounded by O(P) with hash table branching.

    3. Text Scanning:
       Traverses automaton character-by-character over input text of length L.
       Emits Z reported occurrences.
       Total search time: O(L + Z).
    """

    def __init__(self, case_sensitive: bool = False) -> None:
        self.root = TrieNode()
        self.case_sensitive = case_sensitive
        self.signatures: list[Signature] = []
        self._is_built = False

    def add_signature(self, sig: Signature) -> None:
        """Add a signature pattern to the trie."""
        self.signatures.append(sig)
        pat = sig.pattern if self.case_sensitive else sig.pattern.lower()

        curr = self.root
        for char in pat:
            if char not in curr.children:
                curr.children[char] = TrieNode()
            curr = curr.children[char]

        curr.output.append(sig)
        self._is_built = False

    def build(self) -> None:
        """Construct failure transitions and output links via Breadth-First Search."""
        queue: collections.deque[TrieNode] = collections.deque()

        # Depth 1 nodes: failure links point back to root
        for child in self.root.children.values():
            child.fail = self.root
            queue.append(child)

        # BFS for deeper nodes
        while queue:
            curr = queue.popleft()

            for char, child in curr.children.items():
                f = curr.fail
                while f is not None and char not in f.children:
                    f = f.fail

                child.fail = f.children[char] if f is not None else self.root

                # Inherit output matches from failure link state (dictionary link)
                if child.fail.output:
                    child.output = child.output + child.fail.output

                queue.append(child)

        self._is_built = True

    def search(self, text: str) -> list[Match]:
        """Scan input text and report all matching pattern occurrences."""
        if not self._is_built:
            self.build()

        if not text:
            return []

        search_text = text if self.case_sensitive else text.lower()
        matches: list[Match] = []
        curr = self.root

        for idx, char in enumerate(search_text):
            # Follow failure links while transition is missing
            while curr is not self.root and char not in curr.children:
                assert curr.fail is not None
                curr = curr.fail

            if char in curr.children:
                curr = curr.children[char]
            else:
                curr = self.root

            # Emit all matches ending at current index
            if curr.output:
                for sig in curr.output:
                    p_len = len(sig.pattern)
                    start_pos = idx - p_len + 1
                    end_pos = idx + 1
                    matches.append(
                        Match(
                            pattern_id=sig.id,
                            pattern=sig.pattern,
                            product=sig.product,
                            protocol=sig.protocol,
                            start_pos=start_pos,
                            end_pos=end_pos,
                        )
                    )

        # Sort matches by start position, then end position, then pattern_id for determinism
        matches.sort(key=lambda m: (m.start_pos, m.end_pos, m.pattern_id))
        return matches


class NaiveMatcher:
    """Baseline multi-pattern matcher scanning each pattern independently.

    Complexity:
    - Scanning time: O(K * L) where K is signature count and L is text length.
    - Verifies equivalence and provides a benchmark baseline for Aho-Corasick.
    """

    def __init__(self, case_sensitive: bool = False) -> None:
        self.signatures: list[Signature] = []
        self.case_sensitive = case_sensitive

    def add_signature(self, sig: Signature) -> None:
        self.signatures.append(sig)

    def search(self, text: str) -> list[Match]:
        if not text or not self.signatures:
            return []

        search_text = text if self.case_sensitive else text.lower()
        matches: list[Match] = []

        for sig in self.signatures:
            pat = sig.pattern if self.case_sensitive else sig.pattern.lower()
            p_len = len(pat)
            if not pat:
                continue

            start = 0
            while True:
                pos = search_text.find(pat, start)
                if pos == -1:
                    break
                matches.append(
                    Match(
                        pattern_id=sig.id,
                        pattern=sig.pattern,
                        product=sig.product,
                        protocol=sig.protocol,
                        start_pos=pos,
                        end_pos=pos + p_len,
                    )
                )
                # Advance start to find subsequent or overlapping occurrences
                start = pos + 1

        matches.sort(key=lambda m: (m.start_pos, m.end_pos, m.pattern_id))
        return matches


def load_signatures_from_file(filepath: Path | str) -> list[Signature]:
    """Parse JSON signatures file into Signature models."""
    path = Path(filepath)
    if not path.is_file():
        return []

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    signatures = []
    for item in data:
        signatures.append(
            Signature(
                id=item["id"],
                pattern=item["pattern"],
                product=item["product"],
                protocol=item.get("protocol", "Unknown"),
                category=item.get("category", "Unknown"),
            )
        )
    return signatures


def extract_software_version(banner_text: str, product_name: str) -> Optional[str]:
    """Decoupled version extraction heuristic using regex rules.

    Identifying a product name is not sufficient to declare its exact version.
    This helper applies targeted regex patterns following detected product names.
    """
    if not banner_text or not product_name:
        return None

    # Targeted product version extraction regexes
    patterns = [
        # OpenSSH/9.3p1 or OpenSSH_9.3p1
        r"(?:OpenSSH)[/_ ]([0-9]+\.[0-9]+(?:p[0-9]+)?)",
        # nginx/1.24.0
        r"(?:nginx)[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        # Apache/2.4.58
        r"(?:Apache)[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        # vsftpd 3.0.5
        r"(?:vsftpd)[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        # Postfix 3.8.1 or ESMTP Postfix (Ubuntu)
        r"(?:Postfix)[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        # General product_name/x.y.z
        rf"{re.escape(product_name)}[/_ -]([0-9]+(?:\.[0-9]+)+)",
        # Generic version token
        r"version\s*([0-9]+(?:\.[0-9]+)+)",
    ]

    for pat in patterns:
        match = re.search(pat, banner_text, re.IGNORECASE)
        if match:
            return match.group(1)

    return None
