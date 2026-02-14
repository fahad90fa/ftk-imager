from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


def generate_text_report(report_path: Path, case_data: dict[str, Any]) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    bad = case_data.get("bad_sectors") or {}
    seg_hashes = case_data.get("segment_hashes") or {}
    lines = [
        "Forensic Acquisition Report",
        "==========================",
        "",
        f"Case Number: {case_data.get('case_number', '-')}",
        f"Evidence Number: {case_data.get('evidence_number', '-')}",
        f"Examiner: {case_data.get('examiner', '-')}",
        f"Started: {case_data.get('started_at', '-')}",
        f"Completed: {case_data.get('completed_at', '-')}",
        "",
        "Workstation",
        "-----------",
        f"Hostname: {case_data.get('hostname', '-')}",
        f"System state: {case_data.get('system_state_path', '-')}",
        f"Tool info: {json.dumps(case_data.get('tool_info', {}), sort_keys=True)}",
        "",
        "Source Device",
        "-------------",
        f"Path: {case_data.get('source', '-')}",
        f"Metadata file: {case_data.get('metadata_path', '-')}",
        "",
        "Image Output",
        "------------",
        f"Image Path: {case_data.get('image_path', '-')}",
        f"Hashes: {json.dumps(case_data.get('hashes', {}), sort_keys=True)}",
        f"Read Errors: {case_data.get('read_errors', '-')}",
        f"Segment hash summary: {json.dumps(seg_hashes, sort_keys=True)}",
        "",
        "Bad Sector Map",
        "--------------",
        f"Count: {bad.get('bad_sectors_count', '0')}",
        f"JSON: {bad.get('bad_sectors_json', '-')}",
        f"Text: {bad.get('bad_sectors_txt', '-')}",
        "",
        "Audit",
        "-----",
        f"Audit Log: {case_data.get('audit_log', '-')}",
        f"Core Audit Log: {case_data.get('core_audit_log', '-')}",
    ]
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def generate_pdf_report(text_report_path: Path, pdf_path: Path) -> None:
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    if shutil.which("pandoc"):
        subprocess.run(["pandoc", str(text_report_path), "-o", str(pdf_path)], check=True)
        return

    if shutil.which("wkhtmltopdf"):
        html = text_report_path.with_suffix(".html")
        content = text_report_path.read_text(encoding="utf-8")
        html.write_text(f"<html><body><pre>{content}</pre></body></html>", encoding="utf-8")
        subprocess.run(["wkhtmltopdf", str(html), str(pdf_path)], check=True)
        return

    raise RuntimeError("no PDF backend found. Install pandoc or wkhtmltopdf")
