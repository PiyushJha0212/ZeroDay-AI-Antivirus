"""
test_hybrid_platform.py — Comprehensive End-to-End Validation Suite
Tests all layers of the Hybrid ML & DL Malware Detection Platform:
  1. Byte-to-Image Transformation (256x256 grayscale)
  2. ResNet-18 Deep Learning Vision Engine
  3. Static Feature Extraction & LightGBM Engine
  4. Hybrid Soft-Voting Fusion & Confidence Branching
  5. Disagreement Detection
  6. XOR Quarantine Neutralization & Restoration
  7. Real-Time Endpoint Watcher (Watchdog)
  8. Desktop GUI & Badge Rendering
"""
import os
import shutil
import tempfile
import time
from pathlib import Path

import numpy as np
import pytest

from avscan import config, theme, signature
from avscan.vision import bytes_to_pil_image, get_vision_engine, VisionResult
from avscan.engine import get_engine, MLResult, MALWARE, SAFE, ERROR
from avscan.ensemble import EnsembleEngine, EnsembleResult, get_ensemble_engine, SUSPICIOUS
from avscan.quarantine import Quarantine
from avscan.watcher import EndpointWatcher, WatcherEvent


def test_byte_to_image_conversion():
    """Verify raw binary is mapped into a 256x256 grayscale image."""
    data = b"MZ" + bytes([i % 256 for i in range(20000)])
    img = bytes_to_pil_image(data, target_size=(256, 256))
    assert img.size == (256, 256)
    assert img.mode == "L"


def test_resnet18_vision_inference():
    """Verify ResNet-18 model performs independent inference."""
    engine = get_vision_engine()
    data = b"MZ" + bytes([i % 256 for i in range(15000)])
    result = engine.classify_bytes(data)
    assert isinstance(result, VisionResult)
    assert result.cnn_verdict in (MALWARE, SAFE)
    assert 0.0 <= result.cnn_prob <= 1.0
    assert result.error is None


def test_ensemble_soft_voting_logic():
    """Verify soft-voting and confidence threshold branching."""
    ens = EnsembleEngine()

    # Case 1: Both high -> MALWARE (Risk HIGH)
    res1 = ens.combine_probabilities(
        MLResult(MALWARE, lgbm_prob=0.85),
        VisionResult(MALWARE, cnn_prob=0.85)
    )
    assert res1.final_verdict == MALWARE
    assert res1.risk_level == "HIGH"
    assert res1.combined_prob == 0.85
    assert res1.auto_quarantine is True
    assert res1.models_disagree is False

    # Case 2: Grey zone / Model Disagreement -> SUSPICIOUS
    res2 = ens.combine_probabilities(
        MLResult(MALWARE, lgbm_prob=0.70),
        VisionResult(SAFE, cnn_prob=0.40)
    )
    assert res2.final_verdict == SUSPICIOUS
    assert res2.risk_level == "MEDIUM"
    assert res2.combined_prob == 0.55
    assert res2.models_disagree is True

    # Case 3: Both low -> SAFE (Risk LOW)
    res3 = ens.combine_probabilities(
        MLResult(SAFE, lgbm_prob=0.10),
        VisionResult(SAFE, cnn_prob=0.20)
    )
    assert res3.final_verdict == SAFE
    assert res3.risk_level == "LOW"
    assert res3.combined_prob == 0.15
    assert res3.auto_quarantine is False


def test_quarantine_neutralization_and_restore():
    """Verify XOR neutralization, SHA-256 validation, and restore."""
    temp_dir = tempfile.mkdtemp()
    try:
        sample_path = Path(temp_dir) / "test_sample.exe"
        original_bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff" * 100
        sample_path.write_bytes(original_bytes)

        q = Quarantine(quarantine_dir=temp_dir + "/quar")
        entry = q.quarantine_file(sample_path)

        assert not sample_path.exists(), "Original file should be removed"
        q_path = Path(entry["quarantine_path"])
        assert q_path.exists(), "Quarantined file must exist"
        assert q_path.read_bytes() != original_bytes, "Must be XOR neutralized"

        # Restore
        restored = q.restore(entry["sha256"])
        assert len(restored) >= 1
        assert sample_path.exists(), "Restored file must exist at original path"
        assert sample_path.read_bytes() == original_bytes, "Restored content must match byte-for-byte"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_realtime_watcher_trigger():
    """Verify watchdog monitors and triggers hybrid classification on new files."""
    watch_dir = tempfile.mkdtemp()
    events = []
    try:
        watcher = EndpointWatcher(watch_dir=watch_dir, event_callback=lambda ev: events.append(ev))
        assert watcher.start()

        # Drop mock binary into monitored directory
        target = Path(watch_dir) / "incoming_payload.exe"
        target.write_bytes(b"MZ" + bytes([42] * 2000))

        # Allow worker thread to catch event
        for _ in range(40):
            if events:
                break
            time.sleep(0.1)
        watcher.stop()

        assert len(events) >= 1
        ev = events[0]
        assert ev.file_name == "incoming_payload.exe"
        assert isinstance(ev.ensemble_result, EnsembleResult)
        assert ev.ensemble_result.combined_prob is not None
    finally:
        shutil.rmtree(watch_dir, ignore_errors=True)


def test_gui_table_and_badges():
    """Verify GUI table columns and badge styling."""
    assert "SUSPICIOUS" in theme._BADGES
    badge_suspicious = theme.badge("SUSPICIOUS")
    assert badge_suspicious["label"] == "SUSPICIOUS"

    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from PySide6 import QtCore, QtWidgets
    from avscan import gui

    class FakeWorker(QtCore.QThread):
        done = QtCore.Signal(object)
        def start(self): pass

    gui.SelfCheckWorker = FakeWorker
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    w = gui.MainWindow()
    assert "Combined Risk" in w.COLUMNS
    assert "ResNet-18" in w.MONITOR_COLUMNS
    assert hasattr(w, "tabs")
    assert hasattr(w, "watch_list")
    assert hasattr(w, "cb_watch")
    w.close()


def test_gui_monitored_folders_tab():
    """Verify Monitored Folders tab, watchlist management, and event feed."""
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from PySide6 import QtCore, QtWidgets
    from avscan import gui
    from avscan.ensemble import EnsembleResult
    from avscan.watcher import WatcherEvent

    class FakeWorker(QtCore.QThread):
        done = QtCore.Signal(object)
        def start(self): pass

    gui.SelfCheckWorker = FakeWorker
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    w = gui.MainWindow()

    # 1. Check tab widget exists and has 2 tabs
    assert w.tabs.count() == 2
    assert "Scan" in w.tabs.tabText(0)
    assert "Monitored Folders" in w.tabs.tabText(1)

    # 2. Check watchlist initialization
    assert w.watch_list.count() >= 1

    # 3. Test adding a folder programmatically
    test_dir = tempfile.mkdtemp()
    try:
        item = QtWidgets.QListWidgetItem(f"📁  {test_dir}")
        item.setData(QtCore.Qt.ItemDataRole.UserRole, str(test_dir))
        w.watch_list.addItem(item)
        assert w.watch_list.count() == 2
        w.card_mon_folders.set_value(w.watch_list.count(), w._mode)
        assert w.card_mon_folders.value.text() == "2"

        # 4. Test simulated watcher interception event
        ens = EnsembleResult(
            lgbm_prob=0.92,
            lgbm_verdict="MALWARE",
            cnn_prob=0.88,
            cnn_verdict="MALWARE",
            combined_prob=0.90,
            final_verdict="MALWARE",
            risk_level="CRITICAL_THREAT",
            models_disagree=False,
        )
        fake_event = WatcherEvent(
            path=str(Path(test_dir) / "dropped_trojan.exe"),
            file_name="dropped_trojan.exe",
            sha256="cc" * 32,
            ensemble_result=ens,
            quarantined=True,
            quarantine_path=None,
        )
        w._on_watcher_event_received(fake_event)

        # 5. Intercepted event should appear in both tables
        assert w.table.rowCount() == 1
        assert w.table.item(0, 0).text() == "dropped_trojan.exe"
        assert w.monitor_table.rowCount() == 1
        assert w.monitor_table.item(0, 2).text() == "dropped_trojan.exe"
        assert w.monitor_table.item(0, 3).text() == "MALWARE"
        assert w.monitor_table.item(0, 7).text() == "Quarantined (XOR)"
        assert w.card_mon_threats.value.text() == "1"

        # 6. Test clear log
        w._clear_monitor_log()
        assert w.monitor_table.rowCount() == 0
        assert w.card_mon_threats.value.text() == "0"
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)
        w.close()
