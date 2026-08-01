import json
from pathlib import Path

from typer.testing import CliRunner

from malleus.cli import app


runner = CliRunner()


def test_flight_cli_end_to_end(monkeypatch, tmp_path: Path) -> None:
    trace = tmp_path / "trace.jsonl"
    recording = tmp_path / "recording.json"
    graph = tmp_path / "graph.json"
    regressions = tmp_path / "regressions.yaml"
    benchmark = tmp_path / "benchmark.json"
    trace.write_text(
        "\n".join(
            [
                json.dumps({"event_id": "r1", "trace_id": "t1", "event_type": "retrieval"}),
                json.dumps(
                    {
                        "event_id": "p1",
                        "trace_id": "t1",
                        "event_type": "payment",
                        "attributes": {"approved": False},
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )

    captured = runner.invoke(app, ["flight", "capture", str(trace), "--out", str(recording)])
    investigated = runner.invoke(
        app, ["flight", "investigate", str(recording), "--out", str(graph)]
    )
    generated = runner.invoke(
        app,
        ["flight", "regression-generate", str(recording), "--out", str(regressions)],
    )
    scored = runner.invoke(
        app, ["flight", "benchmark-score", str(recording), "--out", str(benchmark)]
    )

    assert captured.exit_code == 0, captured.output
    assert "Violations: 2" in captured.output
    assert investigated.exit_code == 0, investigated.output
    assert generated.exit_code == 0, generated.output
    assert scored.exit_code == 0, scored.output
    assert recording.is_file() and graph.is_file() and regressions.is_file() and benchmark.is_file()

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "report.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("MALLEUS_SIGNING_KEY", "test-secret")
    signed = runner.invoke(app, ["flight", "sign", str(evidence), "--key-id", "test"])
    verified = runner.invoke(
        app,
        [
            "flight",
            "verify",
            str(evidence),
            "--manifest",
            str(evidence / "signed-manifest.json"),
        ],
    )
    assert signed.exit_code == 0, signed.output
    assert verified.exit_code == 0, verified.output
    assert '"valid": true' in verified.output
