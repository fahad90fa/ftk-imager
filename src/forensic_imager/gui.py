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
        from PyQt6.QtCore import QProcess, QProcessEnvironment, Qt  # type: ignore[import-not-found]
        from PyQt6.QtGui import QAction  # type: ignore[import-not-found]
        from PyQt6.QtWidgets import (  # type: ignore[import-not-found]
            QApplication,
            QDialog,
            QDialogButtonBox,
            QFileDialog,
            QFormLayout,
            QHBoxLayout,
            QLabel,
            QLineEdit,
            QMainWindow,
            QMessageBox,
            QPushButton,
            QSplitter,
            QStatusBar,
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
            from PyQt5.QtCore import QProcess, QProcessEnvironment, Qt  # type: ignore[import-not-found]
            from PyQt5.QtWidgets import (  # type: ignore[import-not-found]
                QApplication,
                QAction,
                QDialog,
                QDialogButtonBox,
                QFileDialog,
                QFormLayout,
                QHBoxLayout,
                QLabel,
                QLineEdit,
                QMainWindow,
                QMessageBox,
                QPushButton,
                QSplitter,
                QStatusBar,
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
            self.note = QLabel("Select a physical drive. Drives mounted as '/' are likely system disks.")
            layout.addWidget(self.note)

            self.table = QTableWidget(0, 5)
            self.table.setHorizontalHeaderLabels(["Path", "Type", "Size", "Model", "Mounts"])
            layout.addWidget(self.table)

            btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
            btns.accepted.connect(self._accept)
            btns.rejected.connect(self.reject)
            layout.addWidget(btns)

            self._load()

        def _load(self) -> None:
            devs = lsblk_devices()
            disks = [d for d in devs if d.get("type") == "disk"]
            self.table.setRowCount(0)
            for d in disks:
                r = self.table.rowCount()
                self.table.insertRow(r)
                path = str(d.get("path") or "")
                mounts = d.get("mountpoints") or []
                mounts = [m for m in mounts if m]
                self.table.setItem(r, 0, QTableWidgetItem(path))
                self.table.setItem(r, 1, QTableWidgetItem(str(d.get("type") or "")))
                self.table.setItem(r, 2, QTableWidgetItem(str(d.get("size") or "")))
                self.table.setItem(r, 3, QTableWidgetItem(str(d.get("model") or "")))
                self.table.setItem(r, 4, QTableWidgetItem(", ".join(mounts)))

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
            self.setWindowTitle("Create Disk Image (Raw/DD)")
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
            self.output_dir = QLineEdit("/tmp/CASE-001")
            self.output_image = QLineEdit("/tmp/CASE-001/images/evidence.dd")
            self.output_format = QLineEdit("raw")  # raw|e01
            self.case_number = QLineEdit("CASE-001")
            self.evidence_number = QLineEdit("EVD-001")
            self.examiner = QLineEdit("Examiner")
            self.description = QLineEdit("")
            self.notes = QLineEdit("")

            form.addRow("Source", pick_row)
            form.addRow("Output Dir", self.output_dir)
            form.addRow("Output Image", self.output_image)
            form.addRow("Format (raw|e01)", self.output_format)
            form.addRow("Case Number", self.case_number)
            form.addRow("Evidence Number", self.evidence_number)
            form.addRow("Examiner", self.examiner)
            form.addRow("Description", self.description)
            form.addRow("Notes", self.notes)
            layout.addLayout(form)

            buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
            buttons.accepted.connect(self.accept)
            buttons.rejected.connect(self.reject)
            layout.addWidget(buttons)

        def _pick_source(self) -> None:
            dlg = DevicePickerDialog(self, title="Select Source Drive")
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            self.source.setText(dlg.selected_path)

        def build_command(self) -> list[str]:
            fmt = self.output_format.text().strip().lower() or "raw"
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
            return [
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
            dlg = AcquireDialog(self, core_binary=self.core_path, repo_root=self.repo_root, env=self.env)
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            src = dlg.source.text().strip()
            if src and src.startswith("/dev/") and is_probably_system_disk(src):
                ok = QMessageBox.warning(
                    self,
                    "System Disk Warning",
                    "The selected source appears to contain the mounted root filesystem ('/').\n\n"
                    "Imaging the system disk is risky. Continue anyway?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                if ok != QMessageBox.StandardButton.Yes:
                    return
            cmd = dlg.build_command()
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
            try:
                entries = _fls_list(self.current_image, self.current_partition_sector)
            except Exception as exc:  # noqa: BLE001
                self._error("File Listing Failed", str(exc))
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
