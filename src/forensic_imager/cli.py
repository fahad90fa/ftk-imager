from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from .acquire import AcquireOptions, run_acquisition, run_resume, verify_image
from .audit import verify_audit_chain
from .case_mgmt import export_case_manifest, init_case_workspace, show_case
from .devices import list_block_devices
from .encryption import decrypt_file_aes256, encrypt_file_aes256, generate_keyfile
from .doctor import run_doctor
from .extract import export_file_from_image
from .formats import acquire_e01, convert_image, inspect_aff, verify_e01
from .memory import capture_memory_lime
from .mounting import mount_image_readonly, unmount_image
from .network import acquire_over_ssh
from .preview import preview_evidence
from .profiles import list_profiles, load_profile, save_profile
from .reporting import generate_pdf_report
from .sanitization import generate_sanitization_certificate, wipe_device_blkdiscard, wipe_device_nist
from .seal import create_case_seal, verify_case_seal
from .bundling import create_case_bundle
from .versioning import get_version_info
from .verify_all import verify_case_all
from .writeblock import get_ro_status, set_readonly, set_readwrite


def cmd_list_devices(_: argparse.Namespace) -> int:
    print(json.dumps(list_block_devices(), indent=2))
    return 0


def _build_acquire_options(args: argparse.Namespace) -> AcquireOptions:
    if args.profile:
        prof = load_profile(args.profile)
        for key, value in prof.items():
            if hasattr(args, key) and getattr(args, key) in (None, "", 0, False):
                setattr(args, key, value)

    return AcquireOptions(
        source=args.source,
        output_image=Path(args.output_image),
        output_dir=Path(args.output_dir),
        case_number=args.case_number,
        evidence_number=args.evidence_number,
        examiner=args.examiner,
        description=args.description,
        notes=args.notes,
        buffer_size=args.buffer_size,
        sha512=args.sha512,
        core_binary=Path(args.core_binary),
        start_offset=args.start_offset,
        max_bytes=args.max_bytes,
        append_mode=args.append,
        progress_interval=args.progress_interval,
        require_writeblock=args.require_writeblock,
        try_writeblock=args.try_writeblock,
        auto_seal=args.auto_seal,
        allow_system_disk=args.allow_system_disk,
        allow_dest_on_source=args.allow_dest_on_source,
        split_bytes=args.split_bytes,
        read_error_mode=1 if args.fail_fast_bad_sectors else 0,
        read_retries=args.read_retries,
    )


def cmd_acquire(args: argparse.Namespace) -> int:
    out = run_acquisition(_build_acquire_options(args))
    print(json.dumps(out, indent=2))
    return 0


def cmd_resume(args: argparse.Namespace) -> int:
    if getattr(args, "split_bytes", 0):
        raise SystemExit("resume does not support segmented outputs; do not use --split-bytes with resume")
    out = run_resume(
        source=args.source,
        output_image=Path(args.output_image),
        output_dir=Path(args.output_dir),
        case_number=args.case_number,
        evidence_number=args.evidence_number,
        examiner=args.examiner,
        description=args.description,
        notes=args.notes,
        buffer_size=args.buffer_size,
        sha512=args.sha512,
        core_binary=Path(args.core_binary),
        progress_interval=args.progress_interval,
        require_writeblock=args.require_writeblock,
        try_writeblock=args.try_writeblock,
        auto_seal=args.auto_seal,
        allow_system_disk=args.allow_system_disk,
        allow_dest_on_source=args.allow_dest_on_source,
        read_error_mode=1 if args.fail_fast_bad_sectors else 0,
        read_retries=args.read_retries,
    )
    print(json.dumps(out, indent=2))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    hashes = verify_image(Path(args.image), Path(args.hash_file))
    print(json.dumps(hashes, indent=2, sort_keys=True))
    return 0


def cmd_preview(args: argparse.Namespace) -> int:
    print(preview_evidence(Path(args.path), limit_entries=args.limit), end="")
    return 0


def cmd_mount_ro(args: argparse.Namespace) -> int:
    loopdev = mount_image_readonly(Path(args.image), Path(args.mount_point), offset=args.offset, fstype=args.fstype)
    print(json.dumps({"loop_device": loopdev, "mount_point": args.mount_point}, indent=2))
    return 0


def cmd_unmount_ro(args: argparse.Namespace) -> int:
    unmount_image(Path(args.mount_point), loopdev=args.loop_device)
    print(json.dumps({"status": "ok", "mount_point": args.mount_point}, indent=2))
    return 0


def cmd_memory_capture(args: argparse.Namespace) -> int:
    hashes = capture_memory_lime(
        Path(args.lime_module),
        Path(args.output),
        fmt=args.format,
        audit_log=Path(args.audit_log) if getattr(args, "audit_log", None) else None,
    )
    print(json.dumps({"status": "ok", "output": args.output, "hashes": hashes}, indent=2))
    return 0


def cmd_profiles_save(args: argparse.Namespace) -> int:
    data = {
        "source": args.source,
        "output_dir": args.output_dir,
        "buffer_size": args.buffer_size,
        "sha512": args.sha512,
        "progress_interval": args.progress_interval,
        "core_binary": args.core_binary,
    }
    path = save_profile(args.name, data)
    print(json.dumps({"saved": str(path)}, indent=2))
    return 0


def cmd_profiles_list(_: argparse.Namespace) -> int:
    print(json.dumps(list_profiles(), indent=2))
    return 0


def cmd_acquire_e01(args: argparse.Namespace) -> int:
    acquire_e01(
        source=args.source,
        output_prefix=Path(args.output_prefix),
        case_number=args.case_number,
        evidence_number=args.evidence_number,
        examiner=args.examiner,
        description=args.description,
        notes=args.notes,
        compression_level=args.compression_level,
        segment_size_mb=args.segment_size_mb,
    )
    print(json.dumps({"status": "ok", "output_prefix": args.output_prefix}, indent=2))
    return 0


def cmd_verify_e01(args: argparse.Namespace) -> int:
    output = verify_e01(Path(args.image))
    print(output, end="")
    return 0


def cmd_convert(args: argparse.Namespace) -> int:
    convert_image(Path(args.input), Path(args.output), args.to_format)
    print(json.dumps({"status": "ok", "input": args.input, "output": args.output, "to_format": args.to_format}, indent=2))
    return 0


def cmd_aff_info(args: argparse.Namespace) -> int:
    print(json.dumps(inspect_aff(Path(args.path)), indent=2))
    return 0


def cmd_network_acquire(args: argparse.Namespace) -> int:
    hashes = acquire_over_ssh(
        host=args.host,
        source_path=args.source,
        output_image=Path(args.output_image),
        hash_path=Path(args.hash_file),
        use_sudo=not args.no_sudo,
        buffer_size=args.buffer_size,
    )
    print(json.dumps(hashes, indent=2, sort_keys=True))
    return 0


def cmd_encrypt(args: argparse.Namespace) -> int:
    password, source = _resolve_password(args)
    encrypt_file_aes256(
        Path(args.input),
        Path(args.output),
        password,
        iter_count=args.iter_count,
        metadata_out=Path(args.metadata_out) if args.metadata_out else None,
        password_source=source,
        allow_weak_password=args.allow_weak_password,
    )
    print(json.dumps({"status": "ok", "output": args.output}, indent=2))
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    password, _source = _resolve_password(args)
    decrypt_file_aes256(Path(args.input), Path(args.output), password, iter_count=args.iter_count)
    print(json.dumps({"status": "ok", "output": args.output}, indent=2))
    return 0


def cmd_wipe(args: argparse.Namespace) -> int:
    if args.method == "nist":
        wipe_device_nist(args.device, passes=args.passes, verify=not args.no_verify)
    elif args.method == "blkdiscard":
        wipe_device_blkdiscard(args.device)
    else:
        raise ValueError("unknown wipe method")

    cert_path = Path(args.certificate)
    generate_sanitization_certificate(cert_path, args.device, args.method, args.operator)
    print(json.dumps({"status": "ok", "certificate": str(cert_path)}, indent=2))
    return 0


def cmd_report_pdf(args: argparse.Namespace) -> int:
    generate_pdf_report(Path(args.text_report), Path(args.pdf))
    print(json.dumps({"status": "ok", "pdf": args.pdf}, indent=2))
    return 0


def cmd_case_init(args: argparse.Namespace) -> int:
    path = init_case_workspace(
        case_dir=Path(args.case_dir),
        case_number=args.case_number,
        examiner=args.examiner,
        description=args.description,
        notes=args.notes,
    )
    print(json.dumps({"status": "ok", "workspace": str(path)}, indent=2))
    return 0


def cmd_case_show(args: argparse.Namespace) -> int:
    data = show_case(Path(args.case_dir))
    print(json.dumps(data, indent=2))
    return 0


def cmd_case_manifest(args: argparse.Namespace) -> int:
    out = export_case_manifest(Path(args.case_dir), Path(args.output))
    print(json.dumps({"status": "ok", "manifest": str(out)}, indent=2))
    return 0


def cmd_case_seal(args: argparse.Namespace) -> int:
    out = create_case_seal(
        Path(args.case_dir),
        seal_path=Path(args.seal_out) if args.seal_out else None,
        manifest_path=Path(args.manifest_out) if args.manifest_out else None,
    )
    print(json.dumps({"status": "ok", "seal": str(out)}, indent=2))
    return 0


def cmd_case_verify(args: argparse.Namespace) -> int:
    out = verify_case_seal(Path(args.case_dir), seal_path=Path(args.seal) if args.seal else None)
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


def cmd_verify_audit(args: argparse.Namespace) -> int:
    out = verify_audit_chain(Path(args.log), require_all_signed=not args.allow_unsigned)
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    path = generate_keyfile(Path(args.output), bytes_len=args.bytes_len)
    print(json.dumps({"status": "ok", "keyfile": str(path)}, indent=2))
    return 0


def cmd_export_file(args: argparse.Namespace) -> int:
    export_file_from_image(
        image_path=Path(args.image),
        start_sector=args.start_sector,
        inode=args.inode,
        output_path=Path(args.output),
        audit_log=Path(args.audit_log) if args.audit_log else None,
    )
    print(json.dumps({"status": "ok", "output": args.output}, indent=2))
    return 0


def cmd_doctor(_: argparse.Namespace) -> int:
    checks = [c.__dict__ for c in run_doctor()]
    print(json.dumps(checks, indent=2, sort_keys=True))
    return 0


def cmd_writeblock_status(args: argparse.Namespace) -> int:
    ro = get_ro_status(args.device)
    print(json.dumps({"device": args.device, "read_only": ro}, indent=2))
    return 0


def cmd_writeblock_set(args: argparse.Namespace) -> int:
    set_readonly(args.device)
    ro = get_ro_status(args.device)
    print(json.dumps({"device": args.device, "read_only": ro}, indent=2))
    return 0


def cmd_writeblock_clear(args: argparse.Namespace) -> int:
    set_readwrite(args.device)
    ro = get_ro_status(args.device)
    print(json.dumps({"device": args.device, "read_only": ro}, indent=2))
    return 0


def cmd_version(args: argparse.Namespace) -> int:
    info = get_version_info(Path(args.core_binary) if getattr(args, "core_binary", None) else None)
    print(json.dumps(info, indent=2, sort_keys=True))
    return 0


def cmd_case_bundle(args: argparse.Namespace) -> int:
    out = create_case_bundle(Path(args.case_dir), Path(args.output))
    print(json.dumps({"status": "ok", "bundle": str(out)}, indent=2))
    return 0


def cmd_verify_all(args: argparse.Namespace) -> int:
    out = verify_case_all(Path(args.case_dir))
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


def _resolve_password(args: argparse.Namespace) -> tuple[str, str]:
    if getattr(args, "password", None):
        return str(args.password), "arg"

    if getattr(args, "password_env", None):
        value = os.getenv(str(args.password_env), "")
        if not value:
            raise RuntimeError(f"environment variable is empty or missing: {args.password_env}")
        return value, f"env:{args.password_env}"

    if getattr(args, "password_file", None):
        value = Path(args.password_file).read_text(encoding="utf-8").strip()
        if not value:
            raise RuntimeError(f"password file is empty: {args.password_file}")
        return value, f"file:{args.password_file}"

    prompt1 = getpass.getpass("Password: ")
    prompt2 = getpass.getpass("Confirm password: ")
    if prompt1 != prompt2:
        raise RuntimeError("password confirmation mismatch")
    if not prompt1:
        raise RuntimeError("empty password is not allowed")
    return prompt1, "prompt"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="forensic-imager", description="Forensic imaging tool for Parrot OS")
    sub = p.add_subparsers(dest="cmd", required=True)

    s_list = sub.add_parser("list-devices", help="List block devices")
    s_list.set_defaults(func=cmd_list_devices)

    s_acq = sub.add_parser("acquire", help="Acquire a raw forensic image")
    s_acq.add_argument("--source", required=True)
    s_acq.add_argument("--output-image", required=True)
    s_acq.add_argument("--output-dir", required=True)
    s_acq.add_argument("--case-number", required=True)
    s_acq.add_argument("--evidence-number", required=True)
    s_acq.add_argument("--examiner", required=True)
    s_acq.add_argument("--description", default="")
    s_acq.add_argument("--notes", default="")
    s_acq.add_argument("--buffer-size", type=int, default=4 * 1024 * 1024)
    s_acq.add_argument("--sha512", action="store_true")
    s_acq.add_argument("--core-binary", default="build/forensic-imager-core")
    s_acq.add_argument("--start-offset", type=int, default=0)
    s_acq.add_argument("--max-bytes", type=int, default=0)
    s_acq.add_argument("--append", action="store_true")
    s_acq.add_argument("--progress-interval", type=int, default=1)
    s_acq.add_argument("--profile")
    s_acq.add_argument("--require-writeblock", action="store_true", help="Fail unless source device is RO=1")
    s_acq.add_argument("--try-writeblock", action="store_true", help="Attempt to set RO using blockdev (root)")
    s_acq.add_argument("--auto-seal", action="store_true", help="Seal case after acquisition completes")
    s_acq.add_argument("--allow-system-disk", action="store_true", help="Allow imaging a device that appears to contain '/'")
    s_acq.add_argument("--allow-dest-on-source", action="store_true", help="Allow destination path on the same base disk as source")
    s_acq.add_argument("--split-bytes", type=int, default=0, help="Split raw output into <prefix>.001/.002... with max bytes per segment")
    s_acq.add_argument("--fail-fast-bad-sectors", action="store_true", help="Abort acquisition on first read error")
    s_acq.add_argument("--read-retries", type=int, default=3, help="Retries per read error before applying policy")
    s_acq.set_defaults(func=cmd_acquire)

    s_resume = sub.add_parser("resume", help="Resume interrupted raw acquisition")
    s_resume.add_argument("--source", required=True)
    s_resume.add_argument("--output-image", required=True)
    s_resume.add_argument("--output-dir", required=True)
    s_resume.add_argument("--case-number", required=True)
    s_resume.add_argument("--evidence-number", required=True)
    s_resume.add_argument("--examiner", required=True)
    s_resume.add_argument("--description", default="")
    s_resume.add_argument("--notes", default="")
    s_resume.add_argument("--buffer-size", type=int, default=4 * 1024 * 1024)
    s_resume.add_argument("--sha512", action="store_true")
    s_resume.add_argument("--core-binary", default="build/forensic-imager-core")
    s_resume.add_argument("--progress-interval", type=int, default=1)
    s_resume.add_argument("--require-writeblock", action="store_true")
    s_resume.add_argument("--try-writeblock", action="store_true")
    s_resume.add_argument("--auto-seal", action="store_true")
    s_resume.add_argument("--allow-system-disk", action="store_true")
    s_resume.add_argument("--allow-dest-on-source", action="store_true")
    s_resume.add_argument("--split-bytes", type=int, default=0)
    s_resume.add_argument("--fail-fast-bad-sectors", action="store_true")
    s_resume.add_argument("--read-retries", type=int, default=3)
    s_resume.set_defaults(func=cmd_resume)

    s_verify = sub.add_parser("verify", help="Verify image hash file")
    s_verify.add_argument("--image", required=True)
    s_verify.add_argument("--hash-file", required=True)
    s_verify.set_defaults(func=cmd_verify)

    s_preview = sub.add_parser("preview", help="Read-only evidence preview")
    s_preview.add_argument("--path", required=True)
    s_preview.add_argument("--limit", type=int, default=256)
    s_preview.set_defaults(func=cmd_preview)

    s_mount = sub.add_parser("mount-ro", help="Mount image read-only via loop device")
    s_mount.add_argument("--image", required=True)
    s_mount.add_argument("--mount-point", required=True)
    s_mount.add_argument("--offset", type=int, default=0)
    s_mount.add_argument("--fstype")
    s_mount.set_defaults(func=cmd_mount_ro)

    s_umount = sub.add_parser("unmount-ro", help="Unmount read-only mounted image")
    s_umount.add_argument("--mount-point", required=True)
    s_umount.add_argument("--loop-device")
    s_umount.set_defaults(func=cmd_unmount_ro)

    s_mem = sub.add_parser("memory-capture", help="Capture live memory using LiME module")
    s_mem.add_argument("--lime-module", required=True)
    s_mem.add_argument("--output", required=True)
    s_mem.add_argument("--format", choices=["lime", "padded", "raw"], default="lime")
    s_mem.add_argument("--audit-log")
    s_mem.set_defaults(func=cmd_memory_capture)

    s_prof = sub.add_parser("profiles", help="Profile management")
    prof_sub = s_prof.add_subparsers(dest="profiles_cmd", required=True)
    s_prof_save = prof_sub.add_parser("save", help="Save profile")
    s_prof_save.add_argument("--name", required=True)
    s_prof_save.add_argument("--source", default="")
    s_prof_save.add_argument("--output-dir", default="")
    s_prof_save.add_argument("--buffer-size", type=int, default=4 * 1024 * 1024)
    s_prof_save.add_argument("--sha512", action="store_true")
    s_prof_save.add_argument("--progress-interval", type=int, default=1)
    s_prof_save.add_argument("--core-binary", default="build/forensic-imager-core")
    s_prof_save.set_defaults(func=cmd_profiles_save)
    s_prof_list = prof_sub.add_parser("list", help="List profiles")
    s_prof_list.set_defaults(func=cmd_profiles_list)

    s_e01 = sub.add_parser("acquire-e01", help="Acquire E01 image using libewf tools")
    s_e01.add_argument("--source", required=True)
    s_e01.add_argument("--output-prefix", required=True)
    s_e01.add_argument("--case-number", required=True)
    s_e01.add_argument("--evidence-number", required=True)
    s_e01.add_argument("--examiner", required=True)
    s_e01.add_argument("--description", default="")
    s_e01.add_argument("--notes", default="")
    s_e01.add_argument("--compression-level", type=int, default=6)
    s_e01.add_argument("--segment-size-mb", type=int, default=2048)
    s_e01.set_defaults(func=cmd_acquire_e01)

    s_e01v = sub.add_parser("verify-e01", help="Verify E01 image")
    s_e01v.add_argument("--image", required=True)
    s_e01v.set_defaults(func=cmd_verify_e01)

    s_conv = sub.add_parser("convert", help="Convert forensic image format")
    s_conv.add_argument("--input", required=True)
    s_conv.add_argument("--output", required=True)
    s_conv.add_argument("--to-format", required=True, choices=["raw", "e01", "aff"])
    s_conv.set_defaults(func=cmd_convert)

    s_aff = sub.add_parser("aff-info", help="Inspect AFF image metadata")
    s_aff.add_argument("--path", required=True)
    s_aff.set_defaults(func=cmd_aff_info)

    s_net = sub.add_parser("network-acquire", help="Acquire source over SSH")
    s_net.add_argument("--host", required=True)
    s_net.add_argument("--source", required=True)
    s_net.add_argument("--output-image", required=True)
    s_net.add_argument("--hash-file", required=True)
    s_net.add_argument("--buffer-size", type=int, default=4 * 1024 * 1024)
    s_net.add_argument("--no-sudo", action="store_true")
    s_net.set_defaults(func=cmd_network_acquire)

    s_enc = sub.add_parser("encrypt", help="Encrypt image using AES-256-CBC (OpenSSL)")
    s_enc.add_argument("--input", required=True)
    s_enc.add_argument("--output", required=True)
    s_enc.add_argument("--metadata-out")
    s_enc.add_argument("--iter-count", type=int, default=200000)
    s_enc.add_argument("--allow-weak-password", action="store_true")
    enc_pw = s_enc.add_mutually_exclusive_group()
    enc_pw.add_argument("--password")
    enc_pw.add_argument("--password-env")
    enc_pw.add_argument("--password-file")
    s_enc.set_defaults(func=cmd_encrypt)

    s_dec = sub.add_parser("decrypt", help="Decrypt image using AES-256-CBC (OpenSSL)")
    s_dec.add_argument("--input", required=True)
    s_dec.add_argument("--output", required=True)
    s_dec.add_argument("--iter-count", type=int, default=200000)
    dec_pw = s_dec.add_mutually_exclusive_group()
    dec_pw.add_argument("--password")
    dec_pw.add_argument("--password-env")
    dec_pw.add_argument("--password-file")
    s_dec.set_defaults(func=cmd_decrypt)

    s_wipe = sub.add_parser("wipe", help="Sanitize device")
    s_wipe.add_argument("--device", required=True)
    s_wipe.add_argument("--method", choices=["nist", "blkdiscard"], default="nist")
    s_wipe.add_argument("--passes", type=int, default=1)
    s_wipe.add_argument("--no-verify", action="store_true")
    s_wipe.add_argument("--operator", required=True)
    s_wipe.add_argument("--certificate", required=True)
    s_wipe.set_defaults(func=cmd_wipe)

    s_pdf = sub.add_parser("report-pdf", help="Render text report to PDF")
    s_pdf.add_argument("--text-report", required=True)
    s_pdf.add_argument("--pdf", required=True)
    s_pdf.set_defaults(func=cmd_report_pdf)

    s_case = sub.add_parser("case", help="Case workspace management")
    case_sub = s_case.add_subparsers(dest="case_cmd", required=True)

    s_case_init = case_sub.add_parser("init", help="Initialize case workspace")
    s_case_init.add_argument("--case-dir", required=True)
    s_case_init.add_argument("--case-number", required=True)
    s_case_init.add_argument("--examiner", required=True)
    s_case_init.add_argument("--description", default="")
    s_case_init.add_argument("--notes", default="")
    s_case_init.set_defaults(func=cmd_case_init)

    s_case_show = case_sub.add_parser("show", help="Show case workspace summary")
    s_case_show.add_argument("--case-dir", required=True)
    s_case_show.set_defaults(func=cmd_case_show)

    s_case_manifest = case_sub.add_parser("manifest", help="Export hashed case manifest")
    s_case_manifest.add_argument("--case-dir", required=True)
    s_case_manifest.add_argument("--output", required=True)
    s_case_manifest.set_defaults(func=cmd_case_manifest)

    s_case_seal = case_sub.add_parser("seal", help="Seal case (manifest + audit + key artifact hashes)")
    s_case_seal.add_argument("--case-dir", required=True)
    s_case_seal.add_argument("--seal-out")
    s_case_seal.add_argument("--manifest-out")
    s_case_seal.set_defaults(func=cmd_case_seal)

    s_case_verify = case_sub.add_parser("verify", help="Verify case seal")
    s_case_verify.add_argument("--case-dir", required=True)
    s_case_verify.add_argument("--seal")
    s_case_verify.set_defaults(func=cmd_case_verify)

    s_audit = sub.add_parser("verify-audit", help="Verify tamper-evident audit chain")
    s_audit.add_argument("--log", required=True)
    s_audit.add_argument("--allow-unsigned", action="store_true")
    s_audit.set_defaults(func=cmd_verify_audit)

    s_keygen = sub.add_parser("keygen", help="Generate secure keyfile")
    s_keygen.add_argument("--output", required=True)
    s_keygen.add_argument("--bytes-len", type=int, default=48)
    s_keygen.set_defaults(func=cmd_keygen)

    s_export = sub.add_parser("export-file", help="Export a file from an image using Sleuth Kit icat")
    s_export.add_argument("--image", required=True)
    s_export.add_argument("--start-sector", type=int, required=True)
    s_export.add_argument("--inode", required=True)
    s_export.add_argument("--output", required=True)
    s_export.add_argument("--audit-log")
    s_export.set_defaults(func=cmd_export_file)

    s_doc = sub.add_parser("doctor", help="Environment/dependency diagnostics")
    s_doc.set_defaults(func=cmd_doctor)

    s_wb = sub.add_parser("writeblock", help="Software write-block controls (blockdev)")
    wb_sub = s_wb.add_subparsers(dest="writeblock_cmd", required=True)

    s_wb_status = wb_sub.add_parser("status", help="Show RO status")
    s_wb_status.add_argument("--device", required=True)
    s_wb_status.set_defaults(func=cmd_writeblock_status)

    s_wb_set = wb_sub.add_parser("set", help="Set RO (requires root)")
    s_wb_set.add_argument("--device", required=True)
    s_wb_set.set_defaults(func=cmd_writeblock_set)

    s_wb_clear = wb_sub.add_parser("clear", help="Clear RO (requires root)")
    s_wb_clear.add_argument("--device", required=True)
    s_wb_clear.set_defaults(func=cmd_writeblock_clear)

    s_ver = sub.add_parser("version", help="Show tool/core version info")
    s_ver.add_argument("--core-binary")
    s_ver.set_defaults(func=cmd_version)

    s_all = sub.add_parser("verify-all", help="Verify audit + image hashes + case seal (if present)")
    s_all.add_argument("--case-dir", required=True)
    s_all.set_defaults(func=cmd_verify_all)

    # Case bundle
    s_case_bundle = case_sub.add_parser("bundle", help="Create a tar.gz bundle of the case directory")
    s_case_bundle.add_argument("--case-dir", required=True)
    s_case_bundle.add_argument("--output", required=True)
    s_case_bundle.set_defaults(func=cmd_case_bundle)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
