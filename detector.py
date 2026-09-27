import math
import os
import time
from collections import Counter, deque
from dataclasses import asdict, dataclass

import config
from filetypes import COMPRESSED_EXTENSIONS, TEXT_EXTENSIONS, header_matches, looks_like_text


@dataclass
class Indicator:
    name: str
    weight: int
    detail: str

    def to_dict(self):
        return asdict(self)


def calculate_entropy(data):
    """Shannon entropy in bits per byte: 0 (all the same) to 8 (fully random)."""
    if not data:
        return 0.0

    length = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def read_sample(file_path, size=config.ENTROPY_SAMPLE_BYTES):
    try:
        with open(file_path, "rb") as file:
            return file.read(size)
    except OSError:
        return None


def get_extension(file_path):
    return os.path.splitext(file_path)[1].lower()


def strip_suspicious_extension(file_path):
    """report.txt.locked -> report.txt, so we can find the original file's history."""
    root, extension = os.path.splitext(file_path)
    if extension.lower() in config.SUSPICIOUS_EXTENSIONS:
        return root
    return None


def is_ransom_note(file_path):
    name = os.path.basename(file_path).lower()
    stem, extension = os.path.splitext(name)
    if extension not in config.RANSOM_NOTE_EXTENSIONS:
        return False
    stem = stem.replace("-", "_").replace(" ", "_")
    return any(keyword in stem for keyword in config.RANSOM_NOTE_KEYWORDS)


def analyze_file(file_path, baseline_entropy=None):
    """Return (indicators, entropy) for one file.

    baseline_entropy is the entropy of the file's last clean version, if known.
    """
    indicators = []
    extension = get_extension(file_path)

    if extension in config.SUSPICIOUS_EXTENSIONS:
        indicators.append(Indicator(
            "suspicious_extension", 40, f"Ransomware-style extension '{extension}'"))

    if is_ransom_note(file_path):
        indicators.append(Indicator(
            "ransom_note", 70, "File name looks like a ransom note"))

    data = read_sample(file_path)
    if data is None:
        return indicators, None

    entropy = None
    if len(data) >= config.MIN_ENTROPY_BYTES:
        entropy = calculate_entropy(data)

    if entropy is not None and entropy >= config.ENTROPY_THRESHOLD:
        if baseline_entropy is not None and entropy - baseline_entropy >= config.ENTROPY_JUMP:
            indicators.append(Indicator(
                "entropy_jump", 50,
                f"Entropy rose from {baseline_entropy:.2f} to {entropy:.2f} (content looks encrypted)"))
        elif extension not in COMPRESSED_EXTENSIONS:
            indicators.append(Indicator(
                "high_entropy", 30, f"High entropy {entropy:.2f} for a '{extension or 'no extension'}' file"))

    if header_matches(extension, data) is False:
        indicators.append(Indicator(
            "header_mismatch", 40, f"Content no longer starts with a valid {extension} header"))

    if extension in TEXT_EXTENSIONS and not looks_like_text(data):
        indicators.append(Indicator(
            "text_corrupted", 40, f"A {extension} file now contains binary data"))

    return indicators, entropy


def total_score(indicators):
    return min(100, sum(indicator.weight for indicator in indicators))


def severity_for(score):
    for name, minimum in config.SEVERITY_LEVELS:
        if score >= minimum:
            return name
    return None


SEVERITY_RANK = {None: 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


class ActivityTracker:
    """Counts file events in a sliding time window."""

    def __init__(self, window_seconds=config.ACTIVITY_WINDOW_SECONDS,
                 threshold=config.MAX_FILE_CHANGES_PER_MINUTE):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.events = deque()

    def _prune(self, now):
        while self.events and now - self.events[0] > self.window_seconds:
            self.events.popleft()

    def record(self, now=None):
        now = time.time() if now is None else now
        self.events.append(now)
        self._prune(now)

    def count(self, now=None):
        self._prune(time.time() if now is None else now)
        return len(self.events)

    def is_burst(self, now=None):
        return self.count(now) > self.threshold
