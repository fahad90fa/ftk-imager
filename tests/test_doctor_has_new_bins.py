from forensic_imager.doctor import run_doctor


def test_doctor_includes_metadata_tools() -> None:
    names = {c.name for c in run_doctor()}
    assert "bin:blkid" in names
    assert "bin:sfdisk" in names
    assert "bin:smartctl" in names
    assert "bin:hdparm" in names
