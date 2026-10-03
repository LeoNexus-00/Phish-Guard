"""
history_manager.py - Saves and loads scan history using a JSON file.

The history file contains a JSON list. Each element is one scan, e.g.:

    {
        "scan_id": "20261004014512345678",
        "url": "http://example-login.com/verify-account",
        "timestamp": "2026-10-04 01:45:12",
        "risk_score": 50,
        "risk_level": "Suspicious",
        "features": {...},
        "detected_rules": [...]
    }

Missing or corrupted files are handled gracefully: the program never crashes
because of a bad history file.
"""

import json
import os
import shutil

import config
from models.scan_record import ScanRecord


class HistoryManager:
    """Handles reading, writing, searching and deleting saved scans."""

    def __init__(self, file_path=None, max_entries=None):
        """Create a history manager.

        Args:
            file_path (str, optional): path of the JSON file. Defaults to
                config.HISTORY_FILE. Tests pass a temporary file instead.
            max_entries (int, optional): maximum scans to keep.
        """
        self.file_path = file_path if file_path else config.HISTORY_FILE
        self.max_entries = max_entries if max_entries else config.MAX_HISTORY_ENTRIES
        self.last_warning = ""        # message the UI can show to the user

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------
    def load_history(self):
        """Read all scans from the file and return a list of ScanRecord objects.

        Newest scans come first.
        """
        self.last_warning = ""
        try:
            with open(self.file_path, "r", encoding="utf-8") as file:
                data = json.load(file)
        except FileNotFoundError:
            return []                                  # no scans saved yet
        except json.JSONDecodeError:
            self._backup_corrupted_file()
            return []
        except OSError as error:
            self.last_warning = f"Could not read the history file: {error}"
            return []

        if not isinstance(data, list):
            self._backup_corrupted_file()
            return []

        records = []
        skipped = 0
        for item in data:
            try:
                records.append(ScanRecord.from_dict(item))
            except (KeyError, TypeError, ValueError):
                skipped += 1                           # ignore broken entries
        if skipped > 0:
            self.last_warning = f"{skipped} damaged history entr(ies) were skipped."
        return records

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------
    def _write_history(self, records):
        """Write the given list of ScanRecord objects to the file.

        The data is first written to a temporary file and then renamed. This
        way a crash during writing cannot leave a half-written history file.

        Returns:
            bool: True if saving succeeded.
        """
        data = []
        for record in records:
            data.append(record.to_dict())

        temp_path = self.file_path + ".tmp"
        try:
            folder = os.path.dirname(self.file_path)
            if folder:
                os.makedirs(folder, exist_ok=True)
            with open(temp_path, "w", encoding="utf-8") as file:
                json.dump(data, file, indent=4, ensure_ascii=False)
            os.replace(temp_path, self.file_path)
            return True
        except (OSError, TypeError) as error:
            self.last_warning = f"Could not save the history file: {error}"
            return False

    def save_scan(self, record):
        """Add a new ScanRecord to the top of the history and save it.

        Returns:
            bool: True if saving succeeded.
        """
        records = self.load_history()
        records.insert(0, record)                      # newest first
        if len(records) > self.max_entries:
            records = records[: self.max_entries]      # drop the oldest
        return self._write_history(records)

    def delete_scan(self, scan_id):
        """Delete one scan by its id. Returns True if a scan was removed."""
        records = self.load_history()
        remaining = []
        for record in records:
            if record.scan_id != scan_id:
                remaining.append(record)

        if len(remaining) == len(records):
            return False                               # id not found
        return self._write_history(remaining)

    def clear_history(self):
        """Delete all saved scans. Returns True if successful."""
        return self._write_history([])

    # ------------------------------------------------------------------
    # Searching
    # ------------------------------------------------------------------
    def search(self, text="", risk_levels=None):
        """Return scans whose URL contains `text` and whose level is in `risk_levels`.

        Args:
            text (str): part of a URL to look for (case-insensitive).
            risk_levels (list, optional): allowed risk levels. None = all levels.
        """
        text = text.strip().lower()
        results = []
        for record in self.load_history():
            if text and text not in record.url.lower():
                continue
            if risk_levels is not None and record.risk_level not in risk_levels:
                continue
            results.append(record)
        return results

    # ------------------------------------------------------------------
    # Error recovery
    # ------------------------------------------------------------------
    def _backup_corrupted_file(self):
        """Keep a copy of an unreadable history file so no data is silently lost."""
        backup_path = self.file_path + ".corrupted"
        try:
            shutil.copyfile(self.file_path, backup_path)
            self.last_warning = ("The history file was damaged and could not be read. "
                                 f"A backup was saved as '{os.path.basename(backup_path)}' "
                                 "and a new history will be started.")
        except OSError:
            self.last_warning = "The history file was damaged and could not be read."
