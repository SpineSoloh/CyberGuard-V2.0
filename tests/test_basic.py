"""Basic smoke tests for CyberGuard v2.0."""
import sys
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).parent.parent


def run(*args) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "cyberguard", *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


def test_help():
    r = run("--help")
    assert r.returncode == 0
    assert "cyberguard" in r.stdout.lower()  # CLI binary name stays lowercase


def test_basic_scan_no_consent():
    """Scan with all sensitive collection disabled — should always succeed."""
    r = run("--no-threat-feeds", "--no-browser", "--no-shell", "--no-vt")
    assert r.returncode in (0, 1, 2)  # 1/2 = risks found, still valid
    assert "CyberGuard" in r.stdout


def test_json_output(tmp_path):
    out = tmp_path / "report.json"
    r = run("--no-threat-feeds", "--no-browser", "--no-shell", "--no-vt",
            "--json", "--output", str(out))
    assert out.exists()
    data = json.loads(out.read_text())
    assert "risk_assessment" in data
    assert "security_posture" in data
    assert "timestamp" in data


def test_imports():
    from cyberguard.core import (
        PrivilegeChecker, ConsentManager, DependencyChecker,
        NetworkIntelligence, HashIntelligence, BaselineAnalyzer,
        ArtifactCollector, BehavioralAnalyzer, SecurityPosture, Cyberguard,
    )
    assert PrivilegeChecker.is_admin() in (True, False)


def test_hash_intel():
    from cyberguard.core import HashIntelligence
    h = HashIntelligence()
    digest = HashIntelligence.sha256(__file__)
    assert digest is not None
    assert len(digest) == 64


def test_baseline_roundtrip(tmp_path, monkeypatch):
    from cyberguard import core
    monkeypatch.setattr(core.BaselineAnalyzer, "BASELINE_FILE", tmp_path / "baseline.json")
    snap = core.BaselineAnalyzer.build_process_baseline()
    assert isinstance(snap, dict)
    core.BaselineAnalyzer.save_baseline(snap)
    loaded = core.BaselineAnalyzer.load_baseline()
    assert loaded is not None
    assert "processes" in loaded


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
