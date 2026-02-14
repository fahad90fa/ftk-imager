from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


def _repo_root() -> Path:
    # repo_root/src/forensic_imager/gui.py -> parents[2] == repo_root
    return Path(__file__).resolve().parents[2]


def _pythonpath_for_repo(repo_root: Path) -> str:
    src = str((repo_root / "src").resolve())
    existing = os.environ.get("PYTHONPATH", "")
    if not existing:
        return src
    if existing.split(":")[0] == src:
        return existing
    return f"{src}:{existing}"


def _ensure_core_built(repo_root: Path) -> Path:
    core = repo_root / "build" / "forensic-imager-core"
    core_src = repo_root / "src" / "core" / "imager_core.c"
    needs_build = (not core.exists()) or (core_src.exists() and core.stat().st_mtime < core_src.stat().st_mtime)
    if needs_build:
        subprocess.run(["make", "core"], cwd=str(repo_root), check=True)
    if not core.exists():
        raise RuntimeError(f"core binary not found after build: {core}")
    if not os.access(core, os.X_OK):
        raise RuntimeError(f"core binary is not executable: {core}")
    return core.resolve()


def _auto_set_qt_platform() -> None:
    # Let users override explicitly.
    if os.environ.get("QT_QPA_PLATFORM"):
        return

    # Heuristic:
    # - If Wayland is present, prefer wayland to avoid XCB issues under Wayland sessions.
    # - Otherwise if DISPLAY is set, use xcb.
    # - Otherwise fall back to offscreen (useful for headless debugging).
    if os.environ.get("WAYLAND_DISPLAY") or os.environ.get("XDG_SESSION_TYPE") == "wayland":
        os.environ["QT_QPA_PLATFORM"] = "wayland"
        return
    if os.environ.get("DISPLAY"):
        os.environ["QT_QPA_PLATFORM"] = "xcb"
        return
    os.environ["QT_QPA_PLATFORM"] = "offscreen"


def _human_bytes(value: float) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    size = float(value)
    for u in units:
        if size < 1024.0:
            return f"{size:.2f} {u}"
        size /= 1024.0
    return f"{size:.2f} PiB"


def _format_eta(seconds: float) -> str:
    if seconds < 0 or seconds == float("inf"):
        return "--:--:--"
    s = int(seconds)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{sec:02d}"


def _which(binary: str) -> bool:
    cp = subprocess.run(["bash", "-lc", f"command -v {shlex.quote(binary)} >/dev/null 2>&1"], check=False)
    return cp.returncode == 0


def _run_json(cmd: list[str], cwd: Path, env: dict[str, str]) -> dict:
    cp = subprocess.run(cmd, check=True, capture_output=True, text=True, cwd=str(cwd), env=env)
    return json.loads(cp.stdout)


def _extract_total_size(source: str) -> int:
    try:
        cp = subprocess.run(
            ["lsblk", "-b", "-J", "-o", "PATH,SIZE", source],
            check=True,
            capture_output=True,
            text=True,
        )
        data = json.loads(cp.stdout)
        devs = data.get("blockdevices", [])
        if devs:
            return int(devs[0].get("size") or 0)
    except Exception:
        pass

    try:
        return Path(source).stat().st_size
    except Exception:
        return 0


def _hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexs:<{width*3}}  |{asc}|")
    return "\n".join(lines) + ("\n" if lines else "")

def _parse_size_bytes(text: str) -> int:
    """
    Parse a size string into bytes.

    Accepts:
      - "0", "1048576"
      - "650MiB", "2GiB", "4.7GiB"
      - "650MB", "2GB"
      - "2g", "2m", "2k"
      - "238.5G" (as shown by lsblk without -b)
    """
    s = (text or "").strip()
    if not s:
        return 0
    # Plain integer bytes
    try:
        return int(s, 10)
    except ValueError:
        pass

    m = re.match(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Z]+)\s*$", s)
    if not m:
        raise ValueError(f"invalid size: {text!r}")
    num = float(m.group(1))
    unit = m.group(2).lower()

    # Normalize common unit forms
    unit = unit.replace("bytes", "b")
    unit = unit.replace("byte", "b")

    # Binary
    bin_units = {
        "kib": 1024,
        "mib": 1024**2,
        "gib": 1024**3,
        "tib": 1024**4,
        "pib": 1024**5,
        "ki": 1024,
        "mi": 1024**2,
        "gi": 1024**3,
        "ti": 1024**4,
        "pi": 1024**5,
    }
    # Decimal
    dec_units = {
        "kb": 1000,
        "mb": 1000**2,
        "gb": 1000**3,
        "tb": 1000**4,
        "pb": 1000**5,
    }
    short = {
        "k": 1024,
        "m": 1024**2,
        "g": 1024**3,
        "t": 1024**4,
        "p": 1024**5,
        "b": 1,
    }

    if unit in bin_units:
        return int(num * bin_units[unit])
    if unit in dec_units:
        return int(num * dec_units[unit])
    if unit in short:
        return int(num * short[unit])

    raise ValueError(f"unknown unit in size: {text!r}")


@dataclass
class EvidenceItem:
    label: str
    path: Path
    kind: str  # device|image|folder


@dataclass
class PartitionInfo:
    description: str
    start_sector: int


@dataclass
class FileEntry:
    inode: str
    name: str
    entry_type: str
    raw_line: str


def _parse_mmls_partitions(output: str) -> list[PartitionInfo]:
    parts: list[PartitionInfo] = []
    # Heuristic parser: look for lines like "02: 0000002048 0000004096 ..."
    for line in output.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        if not re.match(r"^\d{2}:\s+\d+\s+\d+", line):
            continue
        m = re.match(r"^(\d{2}:)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)$", line)
        if not m:
            continue
        start = int(m.group(2))
        desc = m.group(5).strip()
        parts.append(PartitionInfo(description=desc, start_sector=start))
    return parts


def _parse_fls_line(line: str) -> FileEntry | None:
    # Examples (SleuthKit varies):
    # r/r 128-128-1:  $OrphanFiles
    # r/r 5-128-1:    some.txt
    # d/d 11-128-4:   Windows
    m = re.match(r"^([dr-])\/([dr-])\s+(\S+):\s+(.*)$", line.strip())
    if not m:
        return None
    t = m.group(1)
    inode = m.group(3)
    name = m.group(4)
    entry_type = "dir" if t == "d" else "file"
    return FileEntry(inode=inode, name=name, entry_type=entry_type, raw_line=line)


def _fls_list(image_path: Path, start_sector: int, limit: int = 200) -> list[FileEntry]:
    if not _which("fls"):
        raise RuntimeError("Sleuth Kit not installed (missing fls)")
    cmd = ["fls", "-l", "-o", str(start_sector), str(image_path)]
    cp = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr.strip() or "fls failed")
    entries: list[FileEntry] = []
    for line in cp.stdout.splitlines():
        e = _parse_fls_line(line)
        if e:
            entries.append(e)
        if len(entries) >= limit:
            break
    return entries


def _icat_read(image_path: Path, start_sector: int, inode: str, max_bytes: int = 4096) -> bytes:
    if not _which("icat"):
        raise RuntimeError("Sleuth Kit not installed (missing icat)")
    cmd = ["icat", "-o", str(start_sector), str(image_path), inode]
    cp = subprocess.run(cmd, check=False, capture_output=True)
    if cp.returncode != 0:
        raise RuntimeError((cp.stderr or b"").decode("utf-8", errors="replace").strip() or "icat failed")
    return (cp.stdout or b"")[:max_bytes]


def main() -> int:
    _auto_set_qt_platform()

    # Prefer PyQt6, fallback to PyQt5 (Parrot repos typically ship PyQt5).
    try:
        from PyQt6.QtCore import QProcess, QProcessEnvironment, QTimer, Qt  # type: ignore[import-not-found]
        from PyQt6.QtGui import QAction  # type: ignore[import-not-found]
        from PyQt6.QtWidgets import (  # type: ignore[import-not-found]
            QApplication,
            QCheckBox,
            QComboBox,
            QDialog,
            QDialogButtonBox,
            QFileDialog,
            QFormLayout,
            QHBoxLayout,
            QHeaderView,
            QLabel,
            QLineEdit,
            QListWidget,
            QListWidgetItem,
            QMainWindow,
            QMessageBox,
            QPushButton,
            QSplitter,
            QSpinBox,
            QStackedWidget,
            QStatusBar,
            QStyle,
            QTabWidget,
            QTableWidget,
            QTableWidgetItem,
            QTextEdit,
            QToolBar,
            QTreeWidget,
            QTreeWidgetItem,
            QVBoxLayout,
            QWidget,
        )
        password_echo_mode = QLineEdit.EchoMode.Password
        qt_has_layout_direction = hasattr(Qt, "LayoutDirection")
    except ImportError:
        try:
            from PyQt5.QtCore import QProcess, QProcessEnvironment, QTimer, Qt  # type: ignore[import-not-found]
            from PyQt5.QtWidgets import (  # type: ignore[import-not-found]
                QApplication,
                QAction,
                QCheckBox,
                QComboBox,
                QDialog,
                QDialogButtonBox,
                QFileDialog,
                QFormLayout,
                QHBoxLayout,
                QHeaderView,
                QLabel,
                QLineEdit,
                QListWidget,
                QListWidgetItem,
                QMainWindow,
                QMessageBox,
                QPushButton,
                QSplitter,
                QSpinBox,
                QStackedWidget,
                QStatusBar,
                QStyle,
                QTabWidget,
                QTableWidget,
                QTableWidgetItem,
                QTextEdit,
                QToolBar,
                QTreeWidget,
                QTreeWidgetItem,
                QVBoxLayout,
                QWidget,
            )
            password_echo_mode = QLineEdit.Password
            qt_has_layout_direction = False
        except ImportError:
            print("PyQt is not installed. Install python3-pyqt5 to use the GUI.", file=sys.stderr)
            return 1

    repo_root = _repo_root()
    try:
        core_path = _ensure_core_built(repo_root)
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to build backend core: {exc}", file=sys.stderr)
        return 1

    env = dict(os.environ)
    env["PYTHONPATH"] = _pythonpath_for_repo(repo_root)

    def lsblk_devices() -> list[dict]:
        try:
            cp = subprocess.run(
                ["lsblk", "-J", "-o", "NAME,PATH,SIZE,TYPE,MODEL,SERIAL,RM,RO,MOUNTPOINTS,FSTYPE"],
                check=True,
                capture_output=True,
                text=True,
            )
            return (json.loads(cp.stdout) or {}).get("blockdevices", []) or []
        except Exception:
            return []

    def is_probably_system_disk(dev_path: str) -> bool:
        # Heuristic: if the device or any child has / mounted, treat as system disk.
        try:
            cp = subprocess.run(
                ["lsblk", "-J", "-o", "PATH,MOUNTPOINTS", dev_path],
                check=True,
                capture_output=True,
                text=True,
            )
            data = json.loads(cp.stdout) or {}
            stack = list(data.get("blockdevices", []) or [])
            while stack:
                d = stack.pop()
                mps = d.get("mountpoints") or []
                if any(mp == "/" for mp in mps if mp):
                    return True
                stack.extend(d.get("children") or [])
        except Exception:
            return False
        return False

    class DevicePickerDialog(QDialog):
        def __init__(self, parent: QWidget | None, *, title: str) -> None:
            super().__init__(parent)
            self.setWindowTitle(title)
            self.selected_path: str = ""

            layout = QVBoxLayout(self)
            self.note = QLabel("Select a physical drive. System disks and mounted devices are highlighted.")
            layout.addWidget(self.note)

            top = QWidget()
            top_l = QHBoxLayout(top)
            top_l.setContentsMargins(0, 0, 0, 0)
            self.filter_edit = QLineEdit("")
            self.filter_edit.setPlaceholderText("Filter (path/model/serial)...")
            self.filter_edit.textChanged.connect(self._load)
            self.refresh_btn = QPushButton("Refresh")
            self.refresh_btn.clicked.connect(self._load)
            top_l.addWidget(self.filter_edit)
            top_l.addWidget(self.refresh_btn)
            layout.addWidget(top)

            self.table = QTableWidget(0, 8)
            self.table.setHorizontalHeaderLabels(["Path", "Size", "Model", "Serial", "RO", "Mounts", "FSType", "Warnings"])
            self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)  # type: ignore[attr-defined]
            layout.addWidget(self.table)

            btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
            btns.accepted.connect(self._accept)
            btns.rejected.connect(self.reject)
            layout.addWidget(btns)

            # Auto-refresh to catch hotplug events.
            self.timer = QTimer(self)
            self.timer.setInterval(2000)
            self.timer.timeout.connect(self._load)
            self.timer.start()

            self._load()

        def _load(self) -> None:
            devs = lsblk_devices()
            disks = [d for d in devs if d.get("type") == "disk"]
            self.table.setRowCount(0)
            flt = (self.filter_edit.text() if hasattr(self, "filter_edit") else "") or ""
            flt = flt.strip().lower()
            for d in disks:
                path = str(d.get("path") or "")
                model = str(d.get("model") or "")
                serial = str(d.get("serial") or "")
                if flt:
                    hay = " ".join([path, model, serial]).lower()
                    if flt not in hay:
                        continue

                r = self.table.rowCount()
                self.table.insertRow(r)
                mounts = d.get("mountpoints") or []
                mounts = [m for m in mounts if m]
                ro = bool(d.get("ro"))
                fstype = str(d.get("fstype") or "")

                warnings: list[str] = []
                if is_probably_system_disk(path):
                    warnings.append("SYSTEM")
                if mounts:
                    warnings.append("MOUNTED")
                if not ro:
                    warnings.append("RW")
                warn_s = ", ".join(warnings)

                self.table.setItem(r, 0, QTableWidgetItem(path))
                self.table.setItem(r, 1, QTableWidgetItem(str(d.get("size") or "")))
                self.table.setItem(r, 2, QTableWidgetItem(model))
                self.table.setItem(r, 3, QTableWidgetItem(serial))
                self.table.setItem(r, 4, QTableWidgetItem("RO" if ro else "RW"))
                self.table.setItem(r, 5, QTableWidgetItem(", ".join(mounts)))
                self.table.setItem(r, 6, QTableWidgetItem(fstype))
                self.table.setItem(r, 7, QTableWidgetItem(warn_s))

                # Color cues (avoid relying on red/green only).
                if "SYSTEM" in warnings:
                    for c in range(8):
                        it = self.table.item(r, c)
                        if it:
                            it.setBackground(Qt.GlobalColor.lightGray)  # type: ignore[attr-defined]
                if "RW" in warnings:
                    it = self.table.item(r, 4)
                    if it:
                        it.setBackground(Qt.GlobalColor.yellow)  # type: ignore[attr-defined]

        def _accept(self) -> None:
            items = self.table.selectedItems()
            if not items:
                QMessageBox.warning(self, "No Selection", "Select a drive first.")
                return
            row = items[0].row()
            p = self.table.item(row, 0).text() if self.table.item(row, 0) else ""
            if not p:
                QMessageBox.warning(self, "Invalid Selection", "Missing device path.")
                return
            self.selected_path = p
            self.accept()

    class AddEvidenceDialog(QDialog):
        def __init__(self, parent: QWidget | None) -> None:
            super().__init__(parent)
            self.setWindowTitle("Add Evidence Item")
            self.kind = "image"
            self.path = ""

            layout = QVBoxLayout(self)

            self.btn_drive = QPushButton("Add Physical Drive...")
            self.btn_image = QPushButton("Add Image File...")
            self.btn_folder = QPushButton("Add Contents of Folder...")
            self.btn_drive.clicked.connect(self.pick_drive)
            self.btn_image.clicked.connect(self.pick_image)
            self.btn_folder.clicked.connect(self.pick_folder)

            layout.addWidget(self.btn_drive)
            layout.addWidget(self.btn_image)
            layout.addWidget(self.btn_folder)

            btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
            btns.rejected.connect(self.reject)
            layout.addWidget(btns)

        def pick_drive(self) -> None:
            dlg = DevicePickerDialog(self, title="Select Physical Drive")
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            self.kind = "device"
            self.path = dlg.selected_path
            self.accept()

        def pick_image(self) -> None:
            path_str, _ = QFileDialog.getOpenFileName(self, "Select Image File", str(Path.home()))
            if not path_str:
                return
            self.kind = "image"
            self.path = path_str
            self.accept()

        def pick_folder(self) -> None:
            folder = QFileDialog.getExistingDirectory(self, "Select Folder", str(Path.home()))
            if not folder:
                return
            self.kind = "folder"
            self.path = folder
            self.accept()

    class AcquireDialog(QDialog):
        def __init__(self, parent: QWidget | None, core_binary: Path, repo_root: Path, env: dict[str, str]) -> None:
            super().__init__(parent)
            self.setWindowTitle("Create Disk Image")
            self.core_binary = core_binary
            self.repo_root = repo_root
            self.env = env

            layout = QVBoxLayout(self)
            form = QFormLayout()
            self.source = QLineEdit("")
            pick_row = QWidget()
            pick_layout = QHBoxLayout(pick_row)
            pick_layout.setContentsMargins(0, 0, 0, 0)
            pick_layout.addWidget(self.source)
            self.pick_source_btn = QPushButton("Choose...")
            self.pick_source_btn.clicked.connect(self._pick_source)
            pick_layout.addWidget(self.pick_source_btn)

            # Output dir picker
            outdir_row = QWidget()
            outdir_layout = QHBoxLayout(outdir_row)
            outdir_layout.setContentsMargins(0, 0, 0, 0)
            self.output_dir = QLineEdit("/tmp/CASE-001")
            outdir_layout.addWidget(self.output_dir)
            self.pick_outdir_btn = QPushButton("Browse...")
            self.pick_outdir_btn.clicked.connect(self._pick_output_dir)
            outdir_layout.addWidget(self.pick_outdir_btn)

            # Output image picker
            outimg_row = QWidget()
            outimg_layout = QHBoxLayout(outimg_row)
            outimg_layout.setContentsMargins(0, 0, 0, 0)
            self.output_image = QLineEdit("/tmp/CASE-001/images/evidence.dd")
            outimg_layout.addWidget(self.output_image)
            self.pick_outimg_btn = QPushButton("Browse...")
            self.pick_outimg_btn.clicked.connect(self._pick_output_image)
            outimg_layout.addWidget(self.pick_outimg_btn)

            # Format selector
            self.output_format = QComboBox()
            self.output_format.addItems(["raw", "e01"])
            self.case_number = QLineEdit("CASE-001")
            self.evidence_number = QLineEdit("EVD-001")
            self.examiner = QLineEdit("Examiner")
            self.description = QLineEdit("")
            self.notes = QLineEdit("")

            form.addRow("Source", pick_row)
            form.addRow("Output Dir", outdir_row)
            form.addRow("Output Image/Prefix", outimg_row)
            form.addRow("Format", self.output_format)
            form.addRow("Case Number", self.case_number)
            form.addRow("Evidence Number", self.evidence_number)
            form.addRow("Examiner", self.examiner)
            form.addRow("Description", self.description)
            form.addRow("Notes", self.notes)

            # Acquisition controls (raw only)
            self.split_preset = QComboBox()
            self.split_preset.addItems(
                [
                    "No splitting",
                    "650 MiB (CD)",
                    "2 GiB (compat)",
                    "4.7 GiB (DVD)",
                    "Custom bytes",
                ]
            )
            self.split_bytes = QLineEdit("0")
            split_row = QWidget()
            split_layout = QHBoxLayout(split_row)
            split_layout.setContentsMargins(0, 0, 0, 0)
            split_layout.addWidget(self.split_preset)
            split_layout.addWidget(self.split_bytes)
            self.split_preset.currentIndexChanged.connect(self._on_split_preset)
            self._on_split_preset()

            self.require_writeblock = QCheckBox("Require RO (fail if not write-blocked)")
            self.try_writeblock = QCheckBox("Try to set RO using blockdev (requires root)")
            self.fail_fast = QCheckBox("Fail-fast on read errors (bad sectors)")
            self.read_retries = QSpinBox()
            self.read_retries.setMinimum(0)
            self.read_retries.setMaximum(100)
            self.read_retries.setValue(3)

            self.auto_seal = QCheckBox("Auto-seal case after acquisition")
            self.allow_system_disk = QCheckBox("Allow imaging system disk (DANGEROUS)")
            self.allow_dest_on_source = QCheckBox("Allow destination on source disk (DANGEROUS)")

            form.addRow("Split (raw only)", split_row)
            form.addRow("Write-block", self.require_writeblock)
            form.addRow("", self.try_writeblock)
            form.addRow("Bad sector policy", self.fail_fast)
            form.addRow("Read retries", self.read_retries)
            form.addRow("Post actions", self.auto_seal)
            form.addRow("Overrides", self.allow_system_disk)
            form.addRow("", self.allow_dest_on_source)
            layout.addLayout(form)

            # Command preview (what the GUI will execute).
            layout.addWidget(QLabel("Command Preview"))
            self.cmd_preview = QTextEdit()
            self.cmd_preview.setReadOnly(True)
            layout.addWidget(self.cmd_preview)

            buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
            buttons.accepted.connect(self._on_ok_clicked)
            buttons.rejected.connect(self.reject)
            layout.addWidget(buttons)

            # Keep command preview live.
            for w in [
                self.source,
                self.output_dir,
                self.output_image,
                self.case_number,
                self.evidence_number,
                self.examiner,
                self.description,
                self.notes,
                self.split_bytes,
            ]:
                w.textChanged.connect(self._refresh_command_preview)  # type: ignore[attr-defined]
            self.output_format.currentIndexChanged.connect(self._refresh_command_preview)  # type: ignore[attr-defined]
            self.split_preset.currentIndexChanged.connect(self._refresh_command_preview)  # type: ignore[attr-defined]
            for w in [
                self.require_writeblock,
                self.try_writeblock,
                self.fail_fast,
                self.auto_seal,
                self.allow_system_disk,
                self.allow_dest_on_source,
            ]:
                w.stateChanged.connect(self._refresh_command_preview)  # type: ignore[attr-defined]
            self.read_retries.valueChanged.connect(self._refresh_command_preview)  # type: ignore[attr-defined]
            self._refresh_command_preview()

        def _pick_source(self) -> None:
            dlg = DevicePickerDialog(self, title="Select Source Drive")
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            self.source.setText(dlg.selected_path)

        def _pick_output_dir(self) -> None:
            folder = QFileDialog.getExistingDirectory(self, "Select Output Directory", self.output_dir.text().strip() or str(Path.home()))
            if not folder:
                return
            self.output_dir.setText(folder)

        def _pick_output_image(self) -> None:
            # For E01 this is used as output prefix; for raw, it is the output file path.
            start = self.output_image.text().strip() or str(Path.home() / "evidence.dd")
            path_str, _ = QFileDialog.getSaveFileName(self, "Select Output Image/Prefix", start)
            if not path_str:
                return
            self.output_image.setText(path_str)

        def _on_split_preset(self) -> None:
            label = self.split_preset.currentText()
            if label.startswith("No splitting"):
                self.split_bytes.setText("0")
                self.split_bytes.setEnabled(False)
            elif label.startswith("650"):
                self.split_bytes.setText(str(650 * 1024 * 1024))
                self.split_bytes.setEnabled(False)
            elif label.startswith("2 GiB"):
                self.split_bytes.setText(str(2 * 1024 * 1024 * 1024))
                self.split_bytes.setEnabled(False)
            elif label.startswith("4.7"):
                self.split_bytes.setText(str(int(4.7 * 1024 * 1024 * 1024)))
                self.split_bytes.setEnabled(False)
            else:
                # Custom bytes
                if self.split_bytes.text().strip() in ("", "0"):
                    self.split_bytes.setText(str(2 * 1024 * 1024 * 1024))
                self.split_bytes.setEnabled(True)

        def _refresh_command_preview(self) -> None:
            try:
                cmd = self.build_command()
                self.cmd_preview.setPlainText(" ".join(shlex.quote(c) for c in cmd))
            except Exception as exc:  # noqa: BLE001
                self.cmd_preview.setPlainText(f"<invalid configuration: {exc}>")

        def _on_ok_clicked(self) -> None:
            # Validate required fields early.
            src = self.source.text().strip()
            out_dir = self.output_dir.text().strip()
            out_img = self.output_image.text().strip()
            if not src or not out_dir or not out_img:
                QMessageBox.warning(self, "Missing Fields", "Source, Output Dir, and Output Image/Prefix are required.")
                return

            fmt = self.output_format.currentText().strip().lower() or "raw"
            if fmt == "raw":
                # Preflight safety checks using the same logic as the CLI pipeline.
                try:
                    from forensic_imager.safety import ensure_destination_safe, estimate_source_bytes, source_is_system_disk
                except Exception as exc:  # noqa: BLE001
                    QMessageBox.warning(self, "Safety Check Failed", f"Unable to load safety checks: {exc}")
                    return

                if source_is_system_disk(src) and not self.allow_system_disk.isChecked():
                    QMessageBox.critical(
                        self,
                        "System Disk Blocked",
                        "The selected source appears to contain the system mountpoint '/'.\n\n"
                        "For safety, acquisition is blocked.\n"
                        "If you are absolutely sure, enable: Allow imaging system disk (DANGEROUS).",
                    )
                    return

                # Make sure destination directories exist so we can compute free space.
                try:
                    Path(out_dir).mkdir(parents=True, exist_ok=True)
                    Path(out_img).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
                except Exception:
                    # If we can't create them, the CLI will still fail; warn early.
                    pass

                try:
                    total = estimate_source_bytes(src, max_bytes=0)
                except Exception as exc:  # noqa: BLE001
                    QMessageBox.warning(self, "Safety Check Failed", f"Unable to estimate source size: {exc}")
                    return

                try:
                    ensure_destination_safe(
                        source=src,
                        output_path=Path(out_img).expanduser().resolve().parent,
                        estimated_bytes=int(total),
                        allow_dest_on_source=self.allow_dest_on_source.isChecked(),
                    )
                except Exception as exc:  # noqa: BLE001
                    QMessageBox.critical(self, "Unsafe Destination", str(exc))
                    return

                # Extra confirmation if dangerous overrides are enabled.
                if self.allow_system_disk.isChecked() or self.allow_dest_on_source.isChecked():
                    msg = "You enabled one or more dangerous override options:\n\n"
                    if self.allow_system_disk.isChecked():
                        msg += "- Allow imaging system disk\n"
                    if self.allow_dest_on_source.isChecked():
                        msg += "- Allow destination on source disk\n"
                    msg += "\nProceeding can permanently destroy evidence or the running system if misconfigured.\n\nProceed?"
                    res = QMessageBox.question(self, "Confirm Dangerous Overrides", msg)
                    if res != QMessageBox.StandardButton.Yes:
                        return

            # Accept the dialog.
            self.accept()

        def build_command(self) -> list[str]:
            fmt = self.output_format.currentText().strip().lower() or "raw"
            if fmt == "e01":
                # libewf tools use an output prefix (no extension).
                prefix = self.output_image.text().strip()
                prefix = prefix[:-4] if prefix.lower().endswith(".e01") else prefix
                return [
                    sys.executable,
                    "-m",
                    "forensic_imager.cli",
                    "acquire-e01",
                    "--source",
                    self.source.text().strip(),
                    "--output-prefix",
                    prefix,
                    "--case-number",
                    self.case_number.text().strip(),
                    "--evidence-number",
                    self.evidence_number.text().strip(),
                    "--examiner",
                    self.examiner.text().strip(),
                    "--description",
                    self.description.text().strip(),
                    "--notes",
                    self.notes.text().strip(),
                ]

            # Raw acquisition flags
            cmd = [
                sys.executable,
                "-m",
                "forensic_imager.cli",
                "acquire",
                "--source",
                self.source.text().strip(),
                "--output-image",
                self.output_image.text().strip(),
                "--output-dir",
                self.output_dir.text().strip(),
                "--case-number",
                self.case_number.text().strip(),
                "--evidence-number",
                self.evidence_number.text().strip(),
                "--examiner",
                self.examiner.text().strip(),
                "--description",
                self.description.text().strip(),
                "--notes",
                self.notes.text().strip(),
                "--core-binary",
                str(self.core_binary),
            ]
            try:
                split_b = int(self.split_bytes.text().strip() or "0")
            except ValueError:
                split_b = 0
            if split_b > 0:
                cmd += ["--split-bytes", str(split_b)]
            if self.require_writeblock.isChecked():
                cmd += ["--require-writeblock"]
            if self.try_writeblock.isChecked():
                cmd += ["--try-writeblock"]
            if self.fail_fast.isChecked():
                cmd += ["--fail-fast-bad-sectors"]
            cmd += ["--read-retries", str(int(self.read_retries.value()))]
            if self.auto_seal.isChecked():
                cmd += ["--auto-seal"]
            if self.allow_system_disk.isChecked():
                cmd += ["--allow-system-disk"]
            if self.allow_dest_on_source.isChecked():
                cmd += ["--allow-dest-on-source"]
            return cmd

    class AcquireWizard(QDialog):
        """
        FTK-style acquisition wizard:
          1) Case metadata
          2) Source selection
          3) Destination + format
          4) Options + safety
          5) Confirm (command preview)
        """

        def __init__(self, parent: QWidget | None, core_binary: Path) -> None:
            super().__init__(parent)
            self.setWindowTitle("Acquisition Wizard")
            self.core_binary = core_binary
            self._cmd: list[str] = []

            layout = QVBoxLayout(self)
            body = QSplitter()
            layout.addWidget(body)

            # Left: FTK-like step list.
            self.step_list = QListWidget()
            self.step_list.setMinimumWidth(240)
            self.step_list.currentRowChanged.connect(self._on_step_clicked)
            body.addWidget(self.step_list)

            # Right: pages.
            self.pages = QStackedWidget()
            body.addWidget(self.pages)
            body.setStretchFactor(0, 1)
            body.setStretchFactor(1, 4)

            # Nav
            nav = QWidget()
            nav_l = QHBoxLayout(nav)
            nav_l.setContentsMargins(0, 0, 0, 0)
            self.back_btn = QPushButton("Back")
            self.next_btn = QPushButton("Next")
            self.cancel_btn = QPushButton("Cancel")
            self.back_btn.clicked.connect(self._back)
            self.next_btn.clicked.connect(self._next)
            self.cancel_btn.clicked.connect(self.reject)
            nav_l.addWidget(self.back_btn)
            nav_l.addWidget(self.next_btn)
            nav_l.addWidget(self.cancel_btn)
            layout.addWidget(nav)

            self._build_pages()
            self._apply_button_icons()
            self._update_nav()

        def command(self) -> list[str]:
            return self._cmd

        def _sp(self, name: str) -> int | None:
            """
            Cross-Qt helper for standard pixmaps. Returns int enum value or None.
            """
            try:
                return int(getattr(QStyle.StandardPixmap, name))  # type: ignore[attr-defined]
            except Exception:
                try:
                    return int(getattr(QStyle, name))  # type: ignore[attr-defined]
                except Exception:
                    return None

        def _std_icon(self, sp_name: str):
            sp = self._sp(sp_name)
            if sp is None:
                return None
            try:
                return self.style().standardIcon(QStyle.StandardPixmap(sp))  # type: ignore[arg-type]
            except Exception:
                try:
                    return self.style().standardIcon(QStyle.StandardPixmap(sp))  # type: ignore[misc]
                except Exception:
                    return None

        def _apply_button_icons(self) -> None:
            # Use standard icons so we don't require an icon theme or extra assets.
            back_icon = self._std_icon("SP_ArrowBack")
            next_icon = self._std_icon("SP_ArrowForward")
            cancel_icon = self._std_icon("SP_DialogCancelButton")
            if back_icon is not None:
                self.back_btn.setIcon(back_icon)
            if next_icon is not None:
                self.next_btn.setIcon(next_icon)
            if cancel_icon is not None:
                self.cancel_btn.setIcon(cancel_icon)

        def _add_step(self, title: str, sp_icon: str) -> None:
            it = QListWidgetItem(title)
            ico = self._std_icon(sp_icon)
            if ico is not None:
                it.setIcon(ico)
            # Steps are navigated via Back/Next; clicking is supported but validated.
            self.step_list.addItem(it)

        def _build_pages(self) -> None:
            # Page 0: Case
            p0 = QWidget()
            p0l = QVBoxLayout(p0)
            p0l.addWidget(QLabel("Case Information"))
            f = QFormLayout()
            self.case_number = QLineEdit("CASE-001")
            self.evidence_number = QLineEdit("EVD-001")
            self.examiner = QLineEdit("Examiner")
            self.description = QLineEdit("")
            self.notes = QLineEdit("")
            f.addRow("Case Number", self.case_number)
            f.addRow("Evidence Number", self.evidence_number)
            f.addRow("Examiner", self.examiner)
            f.addRow("Description", self.description)
            f.addRow("Notes", self.notes)
            p0l.addLayout(f)
            p0l.addWidget(QLabel("Next: choose a source device or image file."))
            self.pages.addWidget(p0)
            self._add_step("Case Info", "SP_FileDialogInfoView")

            # Page 1: Source
            p1 = QWidget()
            p1l = QVBoxLayout(p1)
            p1l.addWidget(QLabel("Source Selection"))
            src_row = QWidget()
            src_l = QHBoxLayout(src_row)
            src_l.setContentsMargins(0, 0, 0, 0)
            self.source = QLineEdit("")
            self.pick_src_btn = QPushButton("Choose Drive...")
            self.pick_src_btn.clicked.connect(self._pick_source_drive)
            self.pick_src_file_btn = QPushButton("Choose File...")
            self.pick_src_file_btn.clicked.connect(self._pick_source_file)
            src_l.addWidget(self.source)
            src_l.addWidget(self.pick_src_btn)
            src_l.addWidget(self.pick_src_file_btn)
            p1l.addWidget(src_row)
            p1l.addWidget(QLabel("Tip: hardware write-blockers are recommended for high-stakes cases."))
            self.pages.addWidget(p1)
            self._add_step("Source", "SP_DriveHDIcon")

            # Page 2: Destination + format
            p2 = QWidget()
            p2l = QVBoxLayout(p2)
            p2l.addWidget(QLabel("Destination and Format"))
            f2 = QFormLayout()
            outdir_row = QWidget()
            outdir_l = QHBoxLayout(outdir_row)
            outdir_l.setContentsMargins(0, 0, 0, 0)
            self.output_dir = QLineEdit("/tmp/CASE-001")
            self.pick_outdir = QPushButton("Browse...")
            self.pick_outdir.clicked.connect(self._pick_output_dir)
            outdir_l.addWidget(self.output_dir)
            outdir_l.addWidget(self.pick_outdir)

            outimg_row = QWidget()
            outimg_l = QHBoxLayout(outimg_row)
            outimg_l.setContentsMargins(0, 0, 0, 0)
            self.output_image = QLineEdit("/tmp/CASE-001/images/evidence.dd")
            self.pick_outimg = QPushButton("Browse...")
            self.pick_outimg.clicked.connect(self._pick_output_image)
            outimg_l.addWidget(self.output_image)
            outimg_l.addWidget(self.pick_outimg)

            self.format = QComboBox()
            self.format.addItems(["raw", "e01"])

            f2.addRow("Output Dir", outdir_row)
            f2.addRow("Output Image/Prefix", outimg_row)
            f2.addRow("Format", self.format)
            p2l.addLayout(f2)
            self.pages.addWidget(p2)
            self._add_step("Destination", "SP_DirIcon")

            # Page 3: Options + safety
            p3 = QWidget()
            p3l = QVBoxLayout(p3)
            p3l.addWidget(QLabel("Options and Safety"))
            f3 = QFormLayout()

            self.split_preset = QComboBox()
            self.split_preset.addItems(["No splitting", "650 MiB (CD)", "2 GiB (compat)", "4.7 GiB (DVD)", "Custom bytes"])
            self.split_bytes = QLineEdit("0")
            split_row = QWidget()
            split_l = QHBoxLayout(split_row)
            split_l.setContentsMargins(0, 0, 0, 0)
            split_l.addWidget(self.split_preset)
            split_l.addWidget(self.split_bytes)
            self.split_preset.currentIndexChanged.connect(self._on_split_preset)
            self._on_split_preset()

            self.require_writeblock = QCheckBox("Require source RO (fail if not write-blocked)")
            self.try_writeblock = QCheckBox("Try to set RO using blockdev (requires root)")
            self.fail_fast = QCheckBox("Fail-fast on read errors (bad sectors)")
            self.read_retries = QSpinBox()
            self.read_retries.setMinimum(0)
            self.read_retries.setMaximum(100)
            self.read_retries.setValue(3)
            self.sha512 = QCheckBox("Also compute SHA-512 (slower, optional)")
            self.auto_seal = QCheckBox("Auto-seal case after acquisition")

            self.allow_system_disk = QCheckBox("Allow imaging system disk (DANGEROUS)")
            self.allow_dest_on_source = QCheckBox("Allow destination on source disk (DANGEROUS)")

            f3.addRow("Split (raw only)", split_row)
            f3.addRow("Write-block", self.require_writeblock)
            f3.addRow("", self.try_writeblock)
            f3.addRow("Bad sector policy", self.fail_fast)
            f3.addRow("Read retries", self.read_retries)
            f3.addRow("Hashes", self.sha512)
            f3.addRow("Post actions", self.auto_seal)
            f3.addRow("Overrides", self.allow_system_disk)
            f3.addRow("", self.allow_dest_on_source)
            p3l.addLayout(f3)
            p3l.addWidget(QLabel("Next: confirm command and start acquisition."))
            self.pages.addWidget(p3)
            self._add_step("Options", "SP_FileDialogDetailedView")

            # Page 4: Summary + Checklist
            p4 = QWidget()
            p4l = QVBoxLayout(p4)
            p4l.addWidget(QLabel("Summary + Checklist"))
            self.checklist = QTextEdit()
            self.checklist.setReadOnly(True)
            p4l.addWidget(self.checklist)
            p4l.addWidget(QLabel("Command To Execute"))
            self.summary = QTextEdit()
            self.summary.setReadOnly(True)
            self.summary.setMaximumHeight(140)
            p4l.addWidget(self.summary)
            self.pages.addWidget(p4)
            self._add_step("Summary", "SP_DialogApplyButton")

            for w in [
                self.case_number,
                self.evidence_number,
                self.examiner,
                self.description,
                self.notes,
                self.source,
                self.output_dir,
                self.output_image,
                self.split_bytes,
            ]:
                w.textChanged.connect(self._refresh_summary)  # type: ignore[attr-defined]
            self.format.currentIndexChanged.connect(self._refresh_summary)  # type: ignore[attr-defined]
            self.split_preset.currentIndexChanged.connect(self._refresh_summary)  # type: ignore[attr-defined]
            for w in [
                self.require_writeblock,
                self.try_writeblock,
                self.fail_fast,
                self.sha512,
                self.auto_seal,
                self.allow_system_disk,
                self.allow_dest_on_source,
            ]:
                w.stateChanged.connect(self._refresh_summary)  # type: ignore[attr-defined]
            self.read_retries.valueChanged.connect(self._refresh_summary)  # type: ignore[attr-defined]
            self._refresh_summary()
            self.step_list.setCurrentRow(0)

        def _on_split_preset(self) -> None:
            label = self.split_preset.currentText()
            if label.startswith("No splitting"):
                self.split_bytes.setText("0")
                self.split_bytes.setEnabled(False)
            elif label.startswith("650"):
                self.split_bytes.setText(str(650 * 1024 * 1024))
                self.split_bytes.setEnabled(False)
            elif label.startswith("2 GiB"):
                self.split_bytes.setText(str(2 * 1024 * 1024 * 1024))
                self.split_bytes.setEnabled(False)
            elif label.startswith("4.7"):
                self.split_bytes.setText(str(int(4.7 * 1024 * 1024 * 1024)))
                self.split_bytes.setEnabled(False)
            else:
                if self.split_bytes.text().strip() in ("", "0"):
                    self.split_bytes.setText(str(2 * 1024 * 1024 * 1024))
                self.split_bytes.setEnabled(True)

        def _pick_source_drive(self) -> None:
            dlg = DevicePickerDialog(self, title="Select Source Drive")
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            self.source.setText(dlg.selected_path)

        def _pick_source_file(self) -> None:
            path_str, _ = QFileDialog.getOpenFileName(self, "Select Source File", str(Path.home()))
            if not path_str:
                return
            self.source.setText(path_str)

        def _pick_output_dir(self) -> None:
            folder = QFileDialog.getExistingDirectory(self, "Select Output Directory", self.output_dir.text().strip() or str(Path.home()))
            if not folder:
                return
            self.output_dir.setText(folder)

        def _pick_output_image(self) -> None:
            start = self.output_image.text().strip() or str(Path.home() / "evidence.dd")
            path_str, _ = QFileDialog.getSaveFileName(self, "Select Output Image/Prefix", start)
            if not path_str:
                return
            self.output_image.setText(path_str)

        def _build_command(self) -> list[str]:
            fmt = self.format.currentText().strip().lower() or "raw"
            if fmt == "e01":
                prefix = self.output_image.text().strip()
                prefix = prefix[:-4] if prefix.lower().endswith(".e01") else prefix
                return [
                    sys.executable,
                    "-m",
                    "forensic_imager.cli",
                    "acquire-e01",
                    "--source",
                    self.source.text().strip(),
                    "--output-prefix",
                    prefix,
                    "--case-number",
                    self.case_number.text().strip(),
                    "--evidence-number",
                    self.evidence_number.text().strip(),
                    "--examiner",
                    self.examiner.text().strip(),
                    "--description",
                    self.description.text().strip(),
                    "--notes",
                    self.notes.text().strip(),
                ]

            cmd = [
                sys.executable,
                "-m",
                "forensic_imager.cli",
                "acquire",
                "--source",
                self.source.text().strip(),
                "--output-image",
                self.output_image.text().strip(),
                "--output-dir",
                self.output_dir.text().strip(),
                "--case-number",
                self.case_number.text().strip(),
                "--evidence-number",
                self.evidence_number.text().strip(),
                "--examiner",
                self.examiner.text().strip(),
                "--description",
                self.description.text().strip(),
                "--notes",
                self.notes.text().strip(),
                "--core-binary",
                str(self.core_binary),
            ]
            if self.sha512.isChecked():
                cmd += ["--sha512"]
            split_b = _parse_size_bytes(self.split_bytes.text())
            if split_b > 0 and fmt == "raw":
                cmd += ["--split-bytes", str(split_b)]
            if self.require_writeblock.isChecked():
                cmd += ["--require-writeblock"]
            if self.try_writeblock.isChecked():
                cmd += ["--try-writeblock"]
            if self.fail_fast.isChecked():
                cmd += ["--fail-fast-bad-sectors"]
            cmd += ["--read-retries", str(int(self.read_retries.value()))]
            if self.auto_seal.isChecked():
                cmd += ["--auto-seal"]
            if self.allow_system_disk.isChecked():
                cmd += ["--allow-system-disk"]
            if self.allow_dest_on_source.isChecked():
                cmd += ["--allow-dest-on-source"]
            return cmd

        def _build_checklist(self) -> str:
            fmt = self.format.currentText().strip().lower() or "raw"
            src = self.source.text().strip()
            out_img = self.output_image.text().strip()
            out_dir = self.output_dir.text().strip()

            lines: list[str] = []
            ok = "OK"
            warn = "WARN"
            fail = "FAIL"

            def item(status: str, label: str, detail: str = "") -> None:
                if detail:
                    lines.append(f"[{status}] {label}: {detail}")
                else:
                    lines.append(f"[{status}] {label}")

            # Basic presence
            item(ok if src else fail, "Source selected", src or "(missing)")
            item(ok if out_dir else fail, "Output dir set", out_dir or "(missing)")
            item(ok if out_img else fail, "Output image/prefix set", out_img or "(missing)")

            # Hash policy
            alg = "MD5 + SHA1 + SHA256"
            if self.sha512.isChecked():
                alg += " + SHA512"
            item(ok, "Hashes", alg)

            # Raw safety checks (best effort)
            if fmt == "raw" and src and out_img:
                try:
                    from forensic_imager.safety import ensure_destination_safe, estimate_source_bytes, source_is_system_disk
                except Exception as exc:  # noqa: BLE001
                    item(warn, "Safety checks available", f"unable to import: {exc}")
                else:
                    sysdisk = False
                    try:
                        sysdisk = bool(source_is_system_disk(src))
                    except Exception as exc:  # noqa: BLE001
                        item(warn, "System disk detection", str(exc))
                    else:
                        if sysdisk and not self.allow_system_disk.isChecked():
                            item(fail, "System disk protection", "source contains '/' (blocked unless override)")
                        elif sysdisk and self.allow_system_disk.isChecked():
                            item(warn, "System disk override", "enabled")
                        else:
                            item(ok, "System disk protection", "source does not contain '/'")

                    try:
                        total = estimate_source_bytes(src, max_bytes=0)
                        ensure_destination_safe(
                            source=src,
                            output_path=Path(out_img).expanduser().resolve().parent,
                            estimated_bytes=int(total),
                            allow_dest_on_source=self.allow_dest_on_source.isChecked(),
                        )
                    except Exception as exc:  # noqa: BLE001
                        item(fail, "Destination safety", str(exc))
                    else:
                        if self.allow_dest_on_source.isChecked():
                            item(warn, "Destination override", "allow dest on source enabled")
                        else:
                            item(ok, "Destination safety", "passed")

            # Write-block
            if src.startswith("/dev/"):
                try:
                    cp = subprocess.run(["lsblk", "-no", "RO", src], check=False, capture_output=True, text=True)
                    ro = cp.stdout.strip()
                    if ro == "1":
                        item(ok, "Write-block status (lsblk RO)", "RO=1")
                    elif ro == "0":
                        if self.require_writeblock.isChecked():
                            item(fail, "Write-block required", "RO=0 (will be blocked)")
                        else:
                            item(warn, "Write-block status", "RO=0 (consider hardware write-blocker)")
                    else:
                        item(warn, "Write-block status", f"unknown: {ro!r}")
                except Exception as exc:  # noqa: BLE001
                    item(warn, "Write-block status", str(exc))

            # Split settings
            try:
                split_b = _parse_size_bytes(self.split_bytes.text())
            except Exception as exc:  # noqa: BLE001
                split_b = 0
                item(fail, "Split output", f"invalid split size: {exc}")
            if fmt != "raw":
                item(ok, "Split output", "N/A for E01 (use libewf segmentation)")
            else:
                if split_b > 0:
                    item(ok, "Split output", f"{split_b} bytes per segment")
                else:
                    item(ok, "Split output", "disabled")

            # Read error policy
            if self.fail_fast.isChecked():
                item(warn, "Bad sector policy", f"FAIL-FAST after {int(self.read_retries.value())} retries")
            else:
                item(warn, "Bad sector policy", f"CONTINUE (zero-fill) after {int(self.read_retries.value())} retries")

            # Auto seal
            item(ok if self.auto_seal.isChecked() else warn, "Auto-seal case", "enabled" if self.auto_seal.isChecked() else "disabled")

            return "\n".join(lines) + "\n"

        def _refresh_summary(self) -> None:
            try:
                cmd = self._build_command()
                self._cmd = cmd
                self.summary.setPlainText(" ".join(shlex.quote(c) for c in cmd))
                self.checklist.setPlainText(self._build_checklist())
            except Exception as exc:  # noqa: BLE001
                self.summary.setPlainText(f"<invalid configuration: {exc}>")
                self.checklist.setPlainText(f"<invalid configuration: {exc}>")

        def _update_nav(self) -> None:
            idx = self.pages.currentIndex()
            self.back_btn.setEnabled(idx > 0)
            self.step_list.setCurrentRow(idx)
            if idx == self.pages.count() - 1:
                self.next_btn.setText("Start")
            else:
                self.next_btn.setText("Next")

        def _on_step_clicked(self, row: int) -> None:
            if row < 0:
                return
            cur = self.pages.currentIndex()
            if row == cur:
                return
            # Only allow jumping to already-validated pages; validate step-by-step.
            step = cur
            if row > cur:
                while step < row:
                    if not self._validate_page(step):
                        self.step_list.setCurrentRow(cur)
                        return
                    step += 1
            self.pages.setCurrentIndex(row)
            self._update_nav()

        def _back(self) -> None:
            idx = self.pages.currentIndex()
            if idx > 0:
                self.pages.setCurrentIndex(idx - 1)
            self._update_nav()

        def _next(self) -> None:
            idx = self.pages.currentIndex()
            if idx < self.pages.count() - 1:
                if not self._validate_page(idx):
                    return
                self.pages.setCurrentIndex(idx + 1)
                self._update_nav()
                if self.pages.currentIndex() == self.pages.count() - 1:
                    self._refresh_summary()
                return

            # Start pressed
            if not self._validate_page(self.pages.count() - 1):
                return
            self.accept()

        def _validate_page(self, idx: int) -> bool:
            if idx == 0:
                if not self.case_number.text().strip() or not self.evidence_number.text().strip() or not self.examiner.text().strip():
                    QMessageBox.warning(self, "Missing Fields", "Case Number, Evidence Number, and Examiner are required.")
                    return False
                return True

            if idx == 1:
                if not self.source.text().strip():
                    QMessageBox.warning(self, "Missing Source", "Select a source device or file.")
                    return False
                return True

            if idx == 2:
                if not self.output_dir.text().strip() or not self.output_image.text().strip():
                    QMessageBox.warning(self, "Missing Destination", "Output Dir and Output Image/Prefix are required.")
                    return False
                return True

            if idx == 3:
                # Safety preflight on raw only
                fmt = self.format.currentText().strip().lower() or "raw"
                if fmt != "raw":
                    return True
                src = self.source.text().strip()
                out_img = self.output_image.text().strip()
                if not src or not out_img:
                    return True

                # Validate split-bytes field (core requires >= 1MiB if enabled).
                try:
                    split_b = _parse_size_bytes(self.split_bytes.text())
                except Exception as exc:  # noqa: BLE001
                    QMessageBox.warning(self, "Invalid Split Size", f"Split size must be bytes or a size like 2GiB.\n\n{exc}")
                    return False
                if split_b > 0 and split_b < 1024 * 1024:
                    QMessageBox.warning(self, "Invalid Split Size", "Split size must be >= 1 MiB (or 0 to disable).")
                    return False

                try:
                    from forensic_imager.safety import ensure_destination_safe, estimate_source_bytes, source_is_system_disk
                except Exception as exc:  # noqa: BLE001
                    QMessageBox.warning(self, "Safety Check Failed", f"Unable to load safety checks: {exc}")
                    return False

                if source_is_system_disk(src) and not self.allow_system_disk.isChecked():
                    QMessageBox.critical(
                        self,
                        "System Disk Blocked",
                        "The selected source appears to contain the system mountpoint '/'.\n\n"
                        "For safety, acquisition is blocked.\n"
                        "If you are absolutely sure, enable: Allow imaging system disk (DANGEROUS).",
                    )
                    return False

                try:
                    Path(self.output_dir.text().strip()).mkdir(parents=True, exist_ok=True)
                    Path(out_img).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
                except Exception:
                    pass

                try:
                    total = estimate_source_bytes(src, max_bytes=0)
                    ensure_destination_safe(
                        source=src,
                        output_path=Path(out_img).expanduser().resolve().parent,
                        estimated_bytes=int(total),
                        allow_dest_on_source=self.allow_dest_on_source.isChecked(),
                    )
                except Exception as exc:  # noqa: BLE001
                    QMessageBox.critical(self, "Unsafe Destination", str(exc))
                    return False

                if self.allow_system_disk.isChecked() or self.allow_dest_on_source.isChecked():
                    msg = "You enabled one or more dangerous override options:\n\n"
                    if self.allow_system_disk.isChecked():
                        msg += "- Allow imaging system disk\n"
                    if self.allow_dest_on_source.isChecked():
                        msg += "- Allow destination on source disk\n"
                    msg += "\nProceeding can permanently destroy evidence or the running system if misconfigured.\n\nProceed?"
                    res = QMessageBox.question(self, "Confirm Dangerous Overrides", msg)
                    if res != QMessageBox.StandardButton.Yes:
                        return False

                return True

            return True

    class MainWindow(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle("Parrot Forensic Imager")
            self.resize(1280, 820)

            self.repo_root = repo_root
            self.core_path = core_path
            self.env = env

            self.proc: QProcess | None = None
            self.proc_log: QTextEdit | None = None
            self.proc_progress_total_hint = 0
            self.proc_progress_start = 0.0

            self.evidence: list[EvidenceItem] = []
            self.current_image: Path | None = None
            self.current_partition_sector: int = 0
            self.current_folder: Path | None = None

            self._build_actions()
            self._build_menu_toolbar()
            self._build_layout()
            self.setStatusBar(QStatusBar())
            self._log("Core binary: " + str(self.core_path))

        def _build_actions(self) -> None:
            self.act_add_evidence = QAction("Add Evidence Item...", self)
            self.act_add_evidence.triggered.connect(self.add_evidence_item)

            self.act_create_image = QAction("Create Disk Image...", self)
            self.act_create_image.triggered.connect(self.create_disk_image)

            self.act_export_selected = QAction("Export Selected File...", self)
            self.act_export_selected.triggered.connect(self.export_selected_file)

            self.act_verify_audit = QAction("Verify Audit Log...", self)
            self.act_verify_audit.triggered.connect(self.verify_audit)

            self.act_mount_selected = QAction("Mount Selected Partition (RO)...", self)
            self.act_mount_selected.triggered.connect(self.mount_selected_partition)

            self.act_verify_image = QAction("Verify Image Hashes...", self)
            self.act_verify_image.triggered.connect(self.verify_image_hashes)

            self.act_case_seal = QAction("Seal Case...", self)
            self.act_case_seal.triggered.connect(self.case_seal)

            self.act_case_verify = QAction("Verify Case Seal...", self)
            self.act_case_verify.triggered.connect(self.case_verify)

            self.act_case_bundle = QAction("Bundle Case (tar.gz)...", self)
            self.act_case_bundle.triggered.connect(self.case_bundle)

            self.act_exit = QAction("Exit", self)
            self.act_exit.triggered.connect(self.close)

            self.act_doctor = QAction("Diagnostics (doctor)...", self)
            self.act_doctor.triggered.connect(self.run_doctor)

        def _build_menu_toolbar(self) -> None:
            file_menu = self.menuBar().addMenu("File")
            file_menu.addAction(self.act_add_evidence)
            file_menu.addAction(self.act_create_image)
            file_menu.addAction(self.act_export_selected)
            file_menu.addAction(self.act_mount_selected)
            file_menu.addAction(self.act_verify_image)
            file_menu.addSeparator()
            file_menu.addAction(self.act_verify_audit)
            file_menu.addSeparator()
            file_menu.addAction(self.act_exit)

            case_menu = self.menuBar().addMenu("Case")
            case_menu.addAction(self.act_case_seal)
            case_menu.addAction(self.act_case_verify)
            case_menu.addAction(self.act_case_bundle)

            help_menu = self.menuBar().addMenu("Help")
            help_menu.addAction(self.act_doctor)

            tb = QToolBar("Main")
            tb.addAction(self.act_add_evidence)
            tb.addAction(self.act_create_image)
            tb.addAction(self.act_export_selected)
            tb.addAction(self.act_mount_selected)
            tb.addAction(self.act_verify_image)
            tb.addAction(self.act_verify_audit)
            self.addToolBar(tb)

        def _build_layout(self) -> None:
            splitter = QSplitter()

            # Left: Evidence Tree
            self.tree = QTreeWidget()
            self.tree.setHeaderLabels(["Evidence Items"])
            self.tree.itemSelectionChanged.connect(self._on_tree_select)
            splitter.addWidget(self.tree)

            # Right: upper file table, lower tabs
            right = QWidget()
            right_layout = QVBoxLayout(right)

            self.table = QTableWidget(0, 3)
            self.table.setHorizontalHeaderLabels(["Name", "Type", "Inode"]) 
            self.table.itemSelectionChanged.connect(self._on_table_select)
            right_layout.addWidget(self.table)

            self.tabs = QTabWidget()
            self.props = QTextEdit(); self.props.setReadOnly(True)
            self.hex = QTextEdit(); self.hex.setReadOnly(True)
            self.text = QTextEdit(); self.text.setReadOnly(True)
            self.log = QTextEdit(); self.log.setReadOnly(True)
            self.tabs.addTab(self.props, "Properties")
            self.tabs.addTab(self.hex, "Hex")
            self.tabs.addTab(self.text, "Text")
            self.tabs.addTab(self.log, "Log")
            right_layout.addWidget(self.tabs)

            splitter.addWidget(right)
            splitter.setStretchFactor(0, 1)
            splitter.setStretchFactor(1, 3)

            self.setCentralWidget(splitter)

        def _log(self, msg: str) -> None:
            ts = time.strftime("%H:%M:%S")
            self.log.append(f"[{ts}] {msg}")

        def _error(self, title: str, msg: str) -> None:
            self._log(f"ERROR: {title}: {msg}")
            QMessageBox.critical(self, title, msg)

        def _info(self, title: str, msg: str) -> None:
            self._log(f"INFO: {title}: {msg}")
            QMessageBox.information(self, title, msg)

        def add_evidence_item(self) -> None:
            dlg = AddEvidenceDialog(self)
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            p = Path(dlg.path)
            if not p.exists():
                self._error("Not Found", str(p))
                return

            kind = dlg.kind
            label = p.name
            item = EvidenceItem(label=label, path=p, kind=kind)
            self.evidence.append(item)

            root = QTreeWidgetItem([label])
            root.setData(0, 0, {"type": "evidence", "path": str(p), "kind": kind})
            if kind in {"image", "device"}:
                root.addChild(QTreeWidgetItem(["(select to load partitions)"]))
            else:
                root.addChild(QTreeWidgetItem(["(select to browse folder)"]))
            self.tree.addTopLevelItem(root)
            self._log(f"Added evidence: {p}")

        def create_disk_image(self) -> None:
            wiz = AcquireWizard(self, core_binary=self.core_path)
            if wiz.exec() != QDialog.DialogCode.Accepted:
                return
            cmd = wiz.command()
            self._start_process(cmd, target_log=self.log)

        def verify_audit(self) -> None:
            path_str, _ = QFileDialog.getOpenFileName(self, "Verify Audit Log", str(Path.home()))
            if not path_str:
                return
            cmd = [sys.executable, "-m", "forensic_imager.cli", "verify-audit", "--log", path_str]
            self._start_process(cmd, target_log=self.log)

        def verify_image_hashes(self) -> None:
            image_path, _ = QFileDialog.getOpenFileName(self, "Select Image", str(Path.home()))
            if not image_path:
                return
            hash_path, _ = QFileDialog.getOpenFileName(self, "Select Hash File (image.hashes)", str(Path(image_path).parent))
            if not hash_path:
                return
            cmd = [sys.executable, "-m", "forensic_imager.cli", "verify", "--image", image_path, "--hash-file", hash_path]
            self._start_process(cmd, target_log=self.log)

        def case_seal(self) -> None:
            case_dir = QFileDialog.getExistingDirectory(self, "Select Case Directory", str(Path.home()))
            if not case_dir:
                return
            cmd = [sys.executable, "-m", "forensic_imager.cli", "case", "seal", "--case-dir", case_dir]
            self._start_process(cmd, target_log=self.log)

        def case_verify(self) -> None:
            case_dir = QFileDialog.getExistingDirectory(self, "Select Case Directory", str(Path.home()))
            if not case_dir:
                return
            cmd = [sys.executable, "-m", "forensic_imager.cli", "case", "verify", "--case-dir", case_dir]
            self._start_process(cmd, target_log=self.log)

        def case_bundle(self) -> None:
            case_dir = QFileDialog.getExistingDirectory(self, "Select Case Directory", str(Path.home()))
            if not case_dir:
                return
            out_path, _ = QFileDialog.getSaveFileName(self, "Save Bundle", str(Path(case_dir).with_suffix(".tgz")))
            if not out_path:
                return
            cmd = [sys.executable, "-m", "forensic_imager.cli", "case", "bundle", "--case-dir", case_dir, "--output", out_path]
            self._start_process(cmd, target_log=self.log)

        def run_doctor(self) -> None:
            cmd = [sys.executable, "-m", "forensic_imager.cli", "doctor"]
            self._start_process(cmd, target_log=self.log)

        def export_selected_file(self) -> None:
            if self.current_image is None or self.current_partition_sector is None:
                self._error("No Evidence Selected", "Select a partition and a file first.")
                return

            items = self.table.selectedItems()
            if not items:
                self._error("No Selection", "Select a file row first.")
                return

            row = items[0].row()
            inode = self.table.item(row, 2).text() if self.table.item(row, 2) else ""
            name = self.table.item(row, 0).text() if self.table.item(row, 0) else "export.bin"
            entry_type = self.table.item(row, 1).text() if self.table.item(row, 1) else ""
            if entry_type != "file":
                self._error("Not a File", "Selected row is not a file.")
                return

            out_path, _ = QFileDialog.getSaveFileName(self, "Export File", str(Path.home() / name))
            if not out_path:
                return

            cmd = [
                sys.executable,
                "-m",
                "forensic_imager.cli",
                "export-file",
                "--image",
                str(self.current_image),
                "--start-sector",
                str(int(self.current_partition_sector)),
                "--inode",
                inode,
                "--output",
                out_path,
            ]
            self._start_process(cmd, target_log=self.log)

        def mount_selected_partition(self) -> None:
            if self.current_image is None:
                self._error("No Image", "Select an image evidence item and a partition first.")
                return
            # Only meaningful for partitions.
            start_sector = int(self.current_partition_sector or 0)
            offset = start_sector * 512

            mount_point = QFileDialog.getExistingDirectory(self, "Select Mount Point", "/mnt")
            if not mount_point:
                return

            cmd = [
                sys.executable,
                "-m",
                "forensic_imager.cli",
                "mount-ro",
                "--image",
                str(self.current_image),
                "--mount-point",
                mount_point,
                "--offset",
                str(offset),
            ]
            self._start_process(cmd, target_log=self.log)

        def _start_process(self, cmd: list[str], target_log: QTextEdit) -> None:
            if self.proc is not None:
                self._error("Busy", "Another operation is running")
                return

            self.proc = QProcess(self)
            self.proc.setWorkingDirectory(str(self.repo_root))

            pe = QProcessEnvironment.systemEnvironment()
            for k, v in self.env.items():
                pe.insert(k, v)
            self.proc.setProcessEnvironment(pe)

            self.proc.setProgram(cmd[0])
            self.proc.setArguments(cmd[1:])
            self.proc.readyReadStandardOutput.connect(self._on_proc_stdout)
            self.proc.readyReadStandardError.connect(self._on_proc_stderr)
            self.proc.finished.connect(self._on_proc_finished)

            self.proc_log = target_log
            self.proc_progress_total_hint = _extract_total_size(self._maybe_current_source_hint())
            self.proc_progress_start = time.time()

            pretty = " ".join(shlex.quote(x) for x in cmd)
            self._log("$ " + pretty)
            self.statusBar().showMessage("Running...")
            self.proc.start()

        def _maybe_current_source_hint(self) -> str:
            # Best-effort for progress ETA when acquire is running.
            return ""

        def _on_proc_stdout(self) -> None:
            if self.proc is None or self.proc_log is None:
                return
            data = bytes(self.proc.readAllStandardOutput()).decode("utf-8", errors="replace")
            for line in data.splitlines():
                s = line.strip()
                if not s:
                    continue
                try:
                    payload = json.loads(s)
                except json.JSONDecodeError:
                    self.proc_log.append(s)
                    continue

                if "progress_bytes" in payload:
                    pb = int(payload.get("progress_bytes", 0))
                    total = int(payload.get("total_bytes", 0))
                    spd = float(payload.get("speed_bps", 0.0))
                    eta = ""
                    if total > 0 and spd > 0:
                        eta = _format_eta((total - pb) / spd)
                    self.statusBar().showMessage(
                        f"Imaging: {_human_bytes(pb)} / {_human_bytes(total) if total else '?'} @ {_human_bytes(spd)}/s ETA {eta}"
                    )
                    continue

                self.proc_log.append(json.dumps(payload, indent=2, sort_keys=True))

        def _on_proc_stderr(self) -> None:
            if self.proc is None or self.proc_log is None:
                return
            data = bytes(self.proc.readAllStandardError()).decode("utf-8", errors="replace")
            for line in data.splitlines():
                if line.strip():
                    self.proc_log.append("ERR: " + line)

        def _on_proc_finished(self, exit_code: int, _status) -> None:
            self.statusBar().showMessage("Done" if exit_code == 0 else f"Failed (exit {exit_code})")
            self._log(f"Process finished: exit={exit_code}")
            self.proc = None
            self.proc_log = None

        def _on_tree_select(self) -> None:
            items = self.tree.selectedItems()
            if not items:
                return
            node = items[0]
            data = node.data(0, 0)
            if not isinstance(data, dict):
                return

            if data.get("type") == "evidence":
                path = Path(str(data.get("path")))
                kind = str(data.get("kind") or "image")
                if kind in {"image", "device"}:
                    self.current_folder = None
                    self._load_partitions(node, path)
                else:
                    self.current_image = None
                    self.current_partition_sector = 0
                    self.current_folder = path
                    self._load_folder(path)
                return

            if data.get("type") == "partition":
                self.current_image = Path(str(data.get("image")))
                self.current_partition_sector = int(data.get("start_sector", 0))
                self._load_files()
                return

        def _load_partitions(self, node: QTreeWidgetItem, image_path: Path) -> None:
            # Clear placeholder children
            node.takeChildren()

            # SleuthKit does not directly support previewing split raw segments.
            # Make the failure mode explicit to avoid confusing "mmls failed" errors.
            if str(image_path).endswith(".001"):
                self._error(
                    "Segmented Image Preview",
                    "This looks like a segmented raw image (*.001). Preview expects a single raw image file.\n\n"
                    "Reassemble segments into a single .dd file (or acquire without splitting) to preview with Sleuth Kit.",
                )
                return

            if not _which("mmls"):
                self._error("Missing Dependency", "Sleuth Kit not installed (missing mmls). Install sleuthkit.")
                return

            cp = subprocess.run(["mmls", str(image_path)], check=False, capture_output=True, text=True)
            if cp.returncode != 0:
                self._error("mmls failed", (cp.stderr or "").strip() or "mmls failed")
                return

            parts = _parse_mmls_partitions(cp.stdout)
            if not parts:
                # Not partitioned, treat as sector 0 filesystem.
                parts = [PartitionInfo(description="(no partition table)", start_sector=0)]

            for idx, p in enumerate(parts, start=1):
                label = f"Partition {idx}: {p.description} (start {p.start_sector})"
                child = QTreeWidgetItem([label])
                child.setData(0, 0, {"type": "partition", "image": str(image_path), "start_sector": p.start_sector})
                node.addChild(child)

            node.setExpanded(True)
            self._log(f"Loaded partitions for {image_path}")

        def _load_files(self) -> None:
            if self.current_image is None:
                return

            # Best-effort filesystem stats in Properties (helps explain fls failures).
            if _which("fsstat"):
                cp_fs = subprocess.run(
                    ["fsstat", "-o", str(int(self.current_partition_sector)), str(self.current_image)],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if cp_fs.returncode == 0 and cp_fs.stdout.strip():
                    self.props.setPlainText(
                        f"Image: {self.current_image}\nPartition start sector: {self.current_partition_sector}\n\n== fsstat ==\n{cp_fs.stdout}\n"
                    )

            try:
                entries = _fls_list(self.current_image, self.current_partition_sector)
            except Exception as exc:  # noqa: BLE001
                extra = ""
                if _which("fsstat"):
                    cp = subprocess.run(
                        ["fsstat", "-o", str(int(self.current_partition_sector)), str(self.current_image)],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    if cp.stdout.strip():
                        extra = "\n\nfsstat output:\n" + cp.stdout.strip()
                    elif cp.stderr.strip():
                        extra = "\n\nfsstat error:\n" + cp.stderr.strip()
                self._error("File Listing Failed", str(exc) + extra)
                return

            self.table.setRowCount(0)
            for e in entries:
                r = self.table.rowCount()
                self.table.insertRow(r)
                self.table.setItem(r, 0, QTableWidgetItem(e.name))
                self.table.setItem(r, 1, QTableWidgetItem(e.entry_type))
                self.table.setItem(r, 2, QTableWidgetItem(e.inode))
                # stash raw in first cell
                self.table.item(r, 0).setData(0, e.raw_line)

            current_props = self.props.toPlainText().strip()
            if current_props:
                self.props.setPlainText(current_props + f"\nEntries shown: {len(entries)}\n")
            else:
                self.props.setPlainText(
                    f"Image: {self.current_image}\nPartition start sector: {self.current_partition_sector}\nEntries shown: {len(entries)}\n"
                )
            self.hex.setPlainText("")
            self.text.setPlainText("")
            self._log(f"Listed {len(entries)} entries")

        def _load_folder(self, folder: Path) -> None:
            if not folder.exists() or not folder.is_dir():
                self._error("Invalid Folder", str(folder))
                return

            try:
                items = sorted(folder.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
            except Exception as exc:  # noqa: BLE001
                self._error("Folder Read Failed", str(exc))
                return

            self.table.setRowCount(0)
            for p in items[:500]:
                r = self.table.rowCount()
                self.table.insertRow(r)
                self.table.setItem(r, 0, QTableWidgetItem(p.name))
                self.table.setItem(r, 1, QTableWidgetItem("dir" if p.is_dir() else "file"))
                size = str(p.stat().st_size) if p.is_file() else ""
                self.table.setItem(r, 2, QTableWidgetItem(size))
                # Store absolute path in raw_line field slot
                self.table.item(r, 0).setData(0, str(p))

            self.props.setPlainText(f"Folder: {folder}\nEntries shown: {min(len(items), 500)}\n")
            self.hex.setPlainText("")
            self.text.setPlainText("")
            self._log(f"Listed folder entries: {folder}")

        def _on_table_select(self) -> None:
            items = self.table.selectedItems()
            if not items:
                return
            row = items[0].row()
            name = self.table.item(row, 0).text() if self.table.item(row, 0) else ""
            inode = self.table.item(row, 2).text() if self.table.item(row, 2) else ""
            raw = self.table.item(row, 0).data(0) if self.table.item(row, 0) else ""

            self.props.setPlainText(
                "\n".join(
                    [
                        f"Name: {name}",
                        f"Inode: {inode}",
                        f"Type: {self.table.item(row, 1).text() if self.table.item(row, 1) else ''}",
                        "",
                        "Raw:",
                        str(raw),
                    ]
                )
                + "\n"
            )

            if self.current_image is None or not inode or inode == "-":
                # Folder browsing: raw contains the filesystem path.
                if self.current_folder is not None and raw:
                    p = Path(str(raw))
                    if p.is_dir():
                        self.current_folder = p
                        self._load_folder(p)
                        return
                    if p.is_file():
                        try:
                            data = p.read_bytes()[:4096]
                        except Exception as exc:  # noqa: BLE001
                            self.hex.setPlainText(f"(unable to read file)\n{exc}\n")
                            self.text.setPlainText("")
                            return
                        self.hex.setPlainText(_hexdump(data))
                        self.text.setPlainText(data.decode("utf-8", errors="replace"))
                return

            try:
                data = _icat_read(self.current_image, self.current_partition_sector, inode)
            except Exception as exc:  # noqa: BLE001
                self.hex.setPlainText(f"(unable to read content)\n{exc}\n")
                self.text.setPlainText("")
                return

            self.hex.setPlainText(_hexdump(data))
            self.text.setPlainText(data.decode("utf-8", errors="replace"))

    app = QApplication(sys.argv)
    app.setApplicationName("Parrot Forensic Imager")
    if qt_has_layout_direction:
        app.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
    else:
        app.setLayoutDirection(Qt.LeftToRight)

    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
