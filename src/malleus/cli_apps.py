from __future__ import annotations

import typer


app = typer.Typer(help="Malleus defensive LLM evaluation harness")
mutations_app = typer.Typer(help="Inspect available prompt mutation transforms")
findings_app = typer.Typer(help="List, show, and export reportable security findings")
flight_app = typer.Typer(help="Capture, investigate, remediate, and govern agent security traces")
issues_app = typer.Typer(help="Export local remediation issues from Malleus findings")
patch_app = typer.Typer(help="Generate defensive patch suggestion artifacts")
campaign_app = typer.Typer(help="Run deterministic multi-step defensive campaigns")
challenge_app = typer.Typer(help="Run local deterministic artifact challenges")
rag_app = typer.Typer(help="Run local fixture RAG security harness checks")
coverage_app = typer.Typer(help="Build attack-surface coverage artifacts")
threat_model_app = typer.Typer(help="Initialize and inspect offline threat models")
workspace_app = typer.Typer(help="Manage local artifact-backed workspaces")
benchmark_app = typer.Typer(help="Run live benchmarks")
visual_lab_app = typer.Typer(help="Generate provider-free visual and artifact fixtures")
safety_tune_app = typer.Typer(
    help="Explore provider-free safety risk surfaces across decoding parameters"
)
code_agent_app = typer.Typer(help="Inspect local code-agent VCS and lifecycle traces")
scenario_app = typer.Typer(help="Generate defensive draft scenario artifacts")
regression_app = typer.Typer(help="Generate and validate provider-free regression packs")
self_mod_app = typer.Typer(help="Inspect proposed self-modification diffs and traces")
studio_app = typer.Typer(
    help="Run the local Studio lab or export a static sanitized studio narrative"
)
taxonomy_app = typer.Typer(help="Write taxonomy garden snapshots and diffs")
ui_harness_app = typer.Typer(help="Plan provider-free local/staging UI harness scaffolds")
target_app = typer.Typer(help="Manage reusable target model configurations")
bundle_app = typer.Typer(help="Manage target bundles for full trace-backed agent runs")
agent_app = typer.Typer(help="Serve and inspect real external-agent adapters")
audit_app = typer.Typer(
    help="Audit generated reports for suspected false positives and weak evidence"
)


def register_subapps() -> None:
    app.add_typer(mutations_app, name="mutations", hidden=True)
    app.add_typer(findings_app, name="findings")
    app.add_typer(flight_app, name="flight")
    app.add_typer(issues_app, name="issues", hidden=True)
    app.add_typer(patch_app, name="patch", hidden=True)
    app.add_typer(campaign_app, name="campaign", hidden=True)
    app.add_typer(challenge_app, name="challenge", hidden=True)
    app.add_typer(rag_app, name="rag", hidden=True)
    app.add_typer(coverage_app, name="coverage", hidden=True)
    app.add_typer(threat_model_app, name="threat-model", hidden=True)
    app.add_typer(workspace_app, name="workspace", hidden=True)
    app.add_typer(benchmark_app, name="benchmark")
    app.add_typer(visual_lab_app, name="visual-lab", hidden=True)
    app.add_typer(safety_tune_app, name="safety-tune", hidden=True)
    app.add_typer(code_agent_app, name="code-agent", hidden=True)
    app.add_typer(scenario_app, name="scenario", hidden=True)
    app.add_typer(regression_app, name="regression", hidden=True)
    app.add_typer(self_mod_app, name="self-mod", hidden=True)
    app.add_typer(studio_app, name="studio", hidden=True)
    app.add_typer(taxonomy_app, name="taxonomy", hidden=True)
    app.add_typer(ui_harness_app, name="ui-harness", hidden=True)
    app.add_typer(target_app, name="target")
    app.add_typer(bundle_app, name="bundle")
    app.add_typer(agent_app, name="agent")
    app.add_typer(audit_app, name="audit")
