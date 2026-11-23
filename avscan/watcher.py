"""
watcher.py — Real-Time Endpoint System Scanner using watchdog.

Monitors directories (e.g. Downloads folder) in real time:
  1. Detects newly arrived executable binaries.
  2. Ensures file download / write completion (ignores .crdownload/.part/.tmp).
  3. Computes SHA-256 hash.
  4. Runs Dual-Engine AI classification (LightGBM static + ResNet-18 vision).
  5. Auto-quarantines threats exceeding confidence threshold (P >= 0.85).
  6. Emits Windows desktop notifications and fires UI callbacks.
"""
from __future__ import annotations

import os
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileMovedEvent
from watchdog.observers import Observer

from . import config
from .ensemble import EnsembleEngine, EnsembleResult, get_ensemble_engine, MALWARE, SUSPICIOUS, SAFE
from .quarantine import Quarantine

IGNORED_INCOMPLETE_EXTS = {".crdownload", ".part", ".tmp", ".download", ".opdownload"}


@dataclass
class WatcherEvent:
    path: str
    file_name: str
    sha256: str
    ensemble_result: EnsembleResult
    quarantined: bool
    quarantine_path: str | None = None


def send_windows_notification(title: str, message: str) -> None:
    """Delivers a native Windows toast notification using PowerShell."""
    try:
        ps_script = f"""
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
        $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
        $textNodes = $template.GetElementsByTagName("text")
        $textNodes.Item(0).AppendChild($template.CreateTextNode('{title}')) > $null
        $textNodes.Item(1).AppendChild($template.CreateTextNode('{message}')) > $null
        $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('AntivirusAI')
        $notification = [Windows.UI.Notifications.ToastNotification::new($template)]
        $notifier.Show($notification)
        """
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        # Fallback to standard console bell / silent pass if powershell fails
        pass


class DownloadWatcherHandler(FileSystemEventHandler):
    """Handles file system events for new downloads and triggers scan pipeline."""

    def __init__(
        self,
        ensemble_engine: EnsembleEngine | None = None,
        quarantine: Quarantine | None = None,
        auto_quarantine_threshold: float = 0.85,
        event_callback: Callable[[WatcherEvent], None] | None = None,
    ):
        super().__init__()
        self.engine = ensemble_engine or get_ensemble_engine()
        self.quarantine = quarantine or Quarantine()
        self.auto_quarantine_threshold = auto_quarantine_threshold
        self.event_callback = event_callback
        self._scanned_hashes: set[str] = set()

    def _wait_for_file_ready(self, path: Path, max_wait: float = 6.0) -> bool:
        """Wait until file is written and can be opened for reading."""
        t0 = time.time()
        while time.time() - t0 < max_wait:
            if not path.exists():
                return False
            try:
                if path.stat().st_size > 0:
                    with open(path, "rb"):
                        return True
            except (OSError, PermissionError):
                pass
            time.sleep(0.3)
        try:
            return path.exists() and path.stat().st_size > 0
        except OSError:
            return False

    def process_file(self, file_path_str: str) -> None:
        path = Path(file_path_str)
        if not path.is_file():
            return

        suffix = path.suffix.lower()
        if suffix in IGNORED_INCOMPLETE_EXTS:
            return
        if suffix not in config.VALID_EXT:
            return

        # Ensure download is finished and readable
        if not self._wait_for_file_ready(path):
            return

        # Run Dual-Engine hybrid classification
        ens_res, sha, size = self.engine.classify_file(path)
        if not sha or sha in self._scanned_hashes:
            return
        self._scanned_hashes.add(sha)

        quarantined = False
        qpath = None

        # Auto-quarantine trigger for high-confidence threats (P >= 0.85)
        combined_prob = ens_res.combined_prob or 0.0
        if ens_res.final_verdict == MALWARE and combined_prob >= self.auto_quarantine_threshold:
            try:
                entry = self.quarantine.quarantine_file(
                    path, sha256=sha, lgbm_prob=ens_res.lgbm_prob
                )
                quarantined = True
                qpath = entry.get("quarantine_path")
            except Exception:
                quarantined = False

        event = WatcherEvent(
            path=str(path),
            file_name=path.name,
            sha256=sha,
            ensemble_result=ens_res,
            quarantined=quarantined,
            quarantine_path=qpath,
        )

        # Notify user if suspicious or malicious
        if ens_res.final_verdict in (MALWARE, SUSPICIOUS):
            status_text = "AUTO-QUARANTINED" if quarantined else "ACTION REQUIRED"
            title = f"⚠️ Threat Detected [{ens_res.final_verdict}]"
            msg = (
                f"File: {path.name}\n"
                f"Risk: {combined_prob * 100:.1f}%\n"
                f"Status: {status_text}"
            )
            send_windows_notification(title, msg)

        if self.event_callback:
            try:
                self.event_callback(event)
            except Exception:
                pass

    def on_created(self, event: FileCreatedEvent) -> None:
        if not event.is_directory:
            threading.Thread(
                target=self.process_file, args=(event.src_path,), daemon=True
            ).start()

    def on_modified(self, event) -> None:
        if not event.is_directory:
            threading.Thread(
                target=self.process_file, args=(event.src_path,), daemon=True
            ).start()

    def on_moved(self, event: FileMovedEvent) -> None:
        # Browser finishes download: e.g. "sample.exe.crdownload" -> "sample.exe"
        if not event.is_directory:
            threading.Thread(
                target=self.process_file, args=(event.dest_path,), daemon=True
            ).start()


class EndpointWatcher:
    """Manages real-time monitoring across one or more directories."""

    def __init__(
        self,
        watch_dirs: list[Path | str] | Path | str | None = None,
        watch_dir: Path | str | None = None,
        event_callback: Callable[[WatcherEvent], None] | None = None,
    ):
        target = watch_dir if watch_dir is not None else watch_dirs
        if target is None:
            self.watch_dirs: list[Path] = [Path.home() / "Downloads"]
        elif isinstance(target, (list, tuple, set)):
            self.watch_dirs = [Path(p) for p in target]
        else:
            self.watch_dirs = [Path(target)]

        self.event_callback = event_callback
        self.observer: Observer | None = None
        self.handler: DownloadWatcherHandler | None = None
        self._watches: dict[str, any] = {}
        self._is_running = False

    @property
    def watch_dir(self) -> Path:
        # Backwards compatibility accessor
        return self.watch_dirs[0] if self.watch_dirs else (Path.home() / "Downloads")

    def start(self) -> bool:
        if self._is_running:
            return True

        self.handler = DownloadWatcherHandler(event_callback=self.event_callback)
        self.observer = Observer()
        self._watches.clear()

        started_any = False
        for p in list(self.watch_dirs):
            try:
                p.mkdir(parents=True, exist_ok=True)
                w = self.observer.schedule(self.handler, str(p), recursive=False)
                self._watches[str(p)] = w
                started_any = True
            except OSError:
                pass

        if started_any:
            self.observer.start()
            self._is_running = True
            return True
        return False

    def add_watch_dir(self, folder: Path | str) -> bool:
        p = Path(folder).resolve()
        if p not in self.watch_dirs:
            self.watch_dirs.append(p)
        if self._is_running and self.observer and self.handler:
            if str(p) not in self._watches:
                try:
                    p.mkdir(parents=True, exist_ok=True)
                    w = self.observer.schedule(self.handler, str(p), recursive=False)
                    self._watches[str(p)] = w
                    return True
                except OSError:
                    return False
        return True

    def remove_watch_dir(self, folder: Path | str) -> bool:
        p = Path(folder).resolve()
        for d in list(self.watch_dirs):
            if d.resolve() == p:
                self.watch_dirs.remove(d)
        if str(p) in self._watches and self.observer:
            try:
                self.observer.unschedule(self._watches[str(p)])
            except Exception:
                pass
            del self._watches[str(p)]
        return True

    def stop(self) -> None:
        if self.observer and self._is_running:
            self.observer.stop()
            self.observer.join(timeout=2)
            self._is_running = False
            self._watches.clear()

    @property
    def is_running(self) -> bool:
        return self._is_running
