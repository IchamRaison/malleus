"use client";

import { useEffect, useMemo, useState } from "react";

type StudioTarget = {
  id: string;
  name: string;
  target_type: string;
  model?: string | null;
  adapter?: string | null;
  source: string;
  path: string;
  config?: Record<string, unknown>;
};

type StudioAttack = {
  id: string;
  title: string;
  mode: "pack" | "benchmark";
  target_types: string[];
  description: string;
  technical_id: string;
  surface: string;
  estimated_cost: string;
  test_count?: number | null;
  dataset_count?: number | null;
  coverage?: string[];
};

type StudioProvider = {
  id: string;
  label: string;
  base_url: string;
  api_key_env: string;
  adapter: string;
  known_models: string[];
  logo_svg?: string | null;
};

type StudioScanProfile = {
  id: string;
  title: string;
  description: string;
  attack_ids: string[];
  max_attacks?: number | null;
  estimated_cost: string;
  tags: string[];
};

type StudioScanPlan = {
  schema_version: string;
  target: StudioTarget;
  profile: StudioScanProfile;
  description: string;
  languages: string[];
  seed: number;
  steps: Array<{
    sequence: number;
    attack_id: string;
    title: string;
    mode: string;
    estimated_cost: string;
    test_count?: number | null;
    coverage: string[];
    threat_tags: string[];
  }>;
  total_tests?: number | null;
  estimated_cost: string;
  threat_groups: Record<string, number>;
};

type DiscoverResult = {
  provider: StudioProvider;
  models: string[];
  target: StudioTarget;
  selected_model: string;
  model_listing_status: string;
  model_listing_error?: string | null;
  inference_status: string;
  inference_error?: string | null;
};

type ProviderKeyStatus = {
  provider_id: string;
  label: string;
  api_key_env: string;
  present: boolean;
  source: "vault" | "environment" | "missing";
  redacted?: string | null;
};

type RunArtifact = {
  path: string;
  name: string;
  kind: string;
  size_bytes: number;
};

type StudioRun = {
  run_id: string;
  target: string;
  attack_id: string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  out_dir: string;
  report_json?: string | null;
  evidence_json?: string | null;
  score?: string | null;
  passed_items: number;
  total_items: number;
  failed_cases: Array<Record<string, unknown>>;
  error?: string | null;
  request_timeout?: number | null;
  max_retries?: number | null;
  provider_in_flight?: boolean;
  cancel_requested?: boolean;
  started_at?: number | null;
  updated_at?: number | null;
  terminal_reason?: string | null;
};

type RunHistoryItem = {
  run: StudioRun;
  artifacts: RunArtifact[];
  event_count: number;
  source: "memory" | "disk";
};

type StudioEvent = {
  run_id: string;
  sequence: number;
  event: string;
  timestamp: number;
  payload: Record<string, unknown>;
};

const DEFAULT_API_BASES = [
  process.env.NEXT_PUBLIC_STUDIO_API_BASE,
  "http://127.0.0.1:8765",
  "http://127.0.0.1:8766"
].filter(Boolean) as string[];

export default function StudioHome() {
  const [mounted, setMounted] = useState(false);
  const [apiBase, setApiBase] = useState(DEFAULT_API_BASES[0] ?? "http://127.0.0.1:8765");
  const [apiBaseInput, setApiBaseInput] = useState(DEFAULT_API_BASES[0] ?? "http://127.0.0.1:8765");
  const [targets, setTargets] = useState<StudioTarget[]>([]);
  const [attacks, setAttacks] = useState<StudioAttack[]>([]);
  const [providers, setProviders] = useState<StudioProvider[]>([]);
  const [scanProfiles, setScanProfiles] = useState<StudioScanProfile[]>([]);
  const [selectedScanProfile, setSelectedScanProfile] = useState("showcase-findings");
  const [scanDescription, setScanDescription] = useState("Public demo agent with RAG, tools, memory, and customer-account boundaries. Prioritize visible findings.");
  const [scanLanguages, setScanLanguages] = useState("en");
  const [scanBudget, setScanBudget] = useState("");
  const [scanSeed, setScanSeed] = useState(42);
  const [scanPlan, setScanPlan] = useState<StudioScanPlan | null>(null);
  const [planningScan, setPlanningScan] = useState(false);
  const [providerKeys, setProviderKeys] = useState<ProviderKeyStatus[]>([]);
  const [runHistory, setRunHistory] = useState<RunHistoryItem[]>([]);
  const [selectedTarget, setSelectedTarget] = useState("");
  const [selectedAttack, setSelectedAttack] = useState("smoke-v1");
  const [selectedProvider, setSelectedProvider] = useState("nvidia");
  const [apiKey, setApiKey] = useState("");
  const [persistKey, setPersistKey] = useState(false);
  const [models, setModels] = useState<string[]>([]);
  const [selectedModel, setSelectedModel] = useState("");
  const [requestTimeout, setRequestTimeout] = useState(120);
  const [maxRetries, setMaxRetries] = useState(1);
  const [discovering, setDiscovering] = useState(false);
  const [discoverStatus, setDiscoverStatus] = useState("");
  const [inferenceReady, setInferenceReady] = useState(false);
  const [activeRun, setActiveRun] = useState<StudioRun | null>(null);
  const [events, setEvents] = useState<StudioEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError("");
      try {
        const loaded = await loadStudioCatalog(apiBase);
        if (cancelled) return;
        setApiBase(loaded.base);
        setApiBaseInput(loaded.base);
        const nextTargets = loaded.targetData.targets ?? [];
        setTargets(nextTargets);
        setAttacks(loaded.attackData.attacks ?? []);
        setScanProfiles(loaded.scanProfileData.profiles ?? []);
        setProviders(loaded.providerData.providers ?? []);
        setProviderKeys(loaded.providerKeyData.provider_keys ?? []);
        setRunHistory(loaded.historyData.runs ?? []);
        setSelectedTarget(nextTargets[0]?.id ?? "");
      } catch (nextError) {
        if (!cancelled) setError(nextError instanceof Error ? nextError.message : "Unable to reach Studio API.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, [apiBase]);

  const compatibleAttacks = useMemo(() => {
    const target = targets.find((item) => item.id === selectedTarget);
    if (!target) return attacks;
    return attacks.filter((attack) => attack.target_types.includes(target.target_type));
  }, [attacks, selectedTarget, targets]);

  useEffect(() => {
    if (compatibleAttacks.length && !compatibleAttacks.some((attack) => attack.id === selectedAttack)) {
      setSelectedAttack(compatibleAttacks[0].id);
    }
  }, [compatibleAttacks, selectedAttack]);

  async function startRun() {
    setError("");
    setRunning(true);
    setEvents([]);
    try {
      const response = await fetch(`${apiBase}/api/runs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: selectedTarget, attack_id: selectedAttack, request_timeout: requestTimeout, max_retries: maxRetries })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Run could not start.");
      setActiveRun(data.run);
      refreshHistory();
      attachEventStream(data.run.run_id);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Run failed to start.");
      setRunning(false);
    }
  }

  async function startScanRun() {
    if (!selectedTarget || !scanPlan) return;
    setError("");
    setRunning(true);
    setEvents([]);
    try {
      const response = await fetch(`${apiBase}/api/scan-runs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: selectedTarget,
          description: scanDescription,
          languages: scanLanguages
            .split(",")
            .map((item) => item.trim())
            .filter(Boolean),
          profile_id: selectedScanProfile,
          max_attacks: scanBudget ? Number(scanBudget) : null,
          seed: scanSeed,
          request_timeout: requestTimeout,
          max_retries: maxRetries
        })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Scan run could not start.");
      setActiveRun(data.run);
      refreshHistory();
      attachEventStream(data.run.run_id);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Scan run failed to start.");
      setRunning(false);
    }
  }

  function attachEventStream(runId: string) {
    const source = new EventSource(`${apiBase}/api/runs/${runId}/events`);
    source.addEventListener("studio.event", (message) => {
      const event = JSON.parse((message as MessageEvent).data) as StudioEvent;
      setEvents((current) => [...current, event]);
      if (["run_completed", "run_failed", "run_cancelled"].includes(event.event)) {
        refreshRun(runId);
        refreshHistory();
      }
    });
    source.addEventListener("studio.done", (message) => {
      setActiveRun(JSON.parse((message as MessageEvent).data) as StudioRun);
      setRunning(false);
      refreshHistory();
      source.close();
    });
    source.onerror = () => {
      refreshRun(runId);
      setRunning(false);
      source.close();
    };
  }

  async function refreshRun(runId: string) {
    const response = await fetch(`${apiBase}/api/runs/${runId}`);
    if (!response.ok) return;
    const data = await response.json();
    setActiveRun(data.run);
    if (["completed", "failed", "cancelled"].includes(data.run.status)) setRunning(false);
  }

  async function loadRunFromHistory(item: RunHistoryItem) {
    setError("");
    setActiveRun(item.run);
    setRunning(item.run.status === "queued" || item.run.status === "running");
    try {
      const [runResponse, eventsResponse] = await Promise.all([
        fetch(`${apiBase}/api/runs/${item.run.run_id}`),
        fetch(`${apiBase}/api/runs/${item.run.run_id}/events.json?limit=1500`)
      ]);
      if (runResponse.ok) {
        const runData = await runResponse.json();
        setActiveRun(runData.run);
        setRunning(runData.run.status === "queued" || runData.run.status === "running");
      }
      if (eventsResponse.ok) {
        const eventData = await eventsResponse.json();
        setEvents(eventData.events ?? []);
      } else {
        setEvents([]);
      }
    } catch (nextError) {
      setEvents([]);
      setError(nextError instanceof Error ? nextError.message : "Run history could not be loaded.");
    }
  }

  async function refreshHistory() {
    const response = await fetch(`${apiBase}/api/run-history`);
    if (!response.ok) return;
    const data = await response.json();
    setRunHistory(data.runs ?? []);
  }

  async function refreshProviderKeys() {
    const response = await fetch(`${apiBase}/api/provider-keys`);
    if (!response.ok) return;
    const data = await response.json();
    setProviderKeys(data.provider_keys ?? []);
  }

  async function cancelRun() {
    if (!activeRun || !["queued", "running"].includes(activeRun.status)) return;
    setError("");
    setRunning(false);
    try {
      const response = await fetch(`${apiBase}/api/runs/${activeRun.run_id}/cancel`, { method: "POST" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Run could not be cancelled.");
      setActiveRun(data.run);
      refreshHistory();
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Run could not be cancelled.");
    }
  }

  const selectedAttackData = attacks.find((attack) => attack.id === selectedAttack);
  const selectedTargetData = targets.find((target) => target.id === selectedTarget);
  const selectedProviderData = providers.find((provider) => provider.id === selectedProvider);
  const selectedProviderKey = providerKeys.find((key) => key.provider_id === selectedProvider);
  const activeHistoryItem = activeRun ? runHistory.find((item) => item.run.run_id === activeRun.run_id) : undefined;
  const caseCards = useMemo(() => buildCaseCards(events), [events]);
  const surfaceCards = useMemo(() => buildSurfaceEvidenceCards(events), [events]);
  const progress = useMemo(() => buildRunProgress(events), [events]);
  const technicalEvents = useMemo(
    () => events.filter((event) => !["case_start", "case_end", "system_case_end"].includes(event.event)),
    [events]
  );

  async function discoverModels(modelOverride?: string) {
    setError("");
    setDiscoverStatus("");
    setDiscovering(true);
    try {
      const response = await fetch(`${apiBase}/api/providers/${selectedProvider}/discover`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          api_key: apiKey,
          model: modelOverride || selectedModel || null,
          save_key: persistKey,
          use_saved_key: true
        })
      });
      const data = (await response.json()) as DiscoverResult | { detail?: string };
      if (!response.ok) throw new Error("detail" in data ? data.detail : "Provider discovery failed.");
      const result = data as DiscoverResult;
      setModels(result.models);
      setSelectedModel(result.selected_model);
      setDiscoverStatus(
        result.inference_status === "ready"
          ? `${result.models.length} models discovered from ${result.provider.label}. Inference probe ready.`
          : `${result.models.length} models discovered from ${result.provider.label}, but inference is not ready: ${
              result.inference_error ?? result.inference_status
            }`
      );
      setInferenceReady(result.inference_status === "ready");
      setApiKey("");
      refreshProviderKeys();
      const refreshed = await fetch(`${apiBase}/api/targets`);
      const refreshedData = await refreshed.json();
      setTargets(refreshedData.targets ?? []);
      setSelectedTarget(result.target.id);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Unable to discover provider models.");
    } finally {
      setDiscovering(false);
    }
  }

  async function saveProviderKey() {
    if (!apiKey.trim()) return;
    setError("");
    try {
      const response = await fetch(`${apiBase}/api/provider-keys/${selectedProvider}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ api_key: apiKey })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Provider key could not be saved.");
      setApiKey("");
      await refreshProviderKeys();
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Provider key could not be saved.");
    }
  }

  async function deleteProviderKey() {
    setError("");
    try {
      const response = await fetch(`${apiBase}/api/provider-keys/${selectedProvider}`, { method: "DELETE" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Provider key could not be deleted.");
      setInferenceReady(false);
      await refreshProviderKeys();
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Provider key could not be deleted.");
    }
  }

  async function buildScanPlan() {
    if (!selectedTarget) return;
    setError("");
    setPlanningScan(true);
    try {
      const response = await fetch(`${apiBase}/api/scan-plan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: selectedTarget,
          description: scanDescription,
          languages: scanLanguages
            .split(",")
            .map((item) => item.trim())
            .filter(Boolean),
          profile_id: selectedScanProfile,
          max_attacks: scanBudget ? Number(scanBudget) : null,
          seed: scanSeed
        })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Scan plan could not be generated.");
      setScanPlan(data.plan);
      if (data.plan?.steps?.[0]?.attack_id) setSelectedAttack(data.plan.steps[0].attack_id);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Scan plan could not be generated.");
    } finally {
      setPlanningScan(false);
    }
  }

  if (!mounted) {
    return (
      <main className="shell">
        <header className="topbar">
          <div>
            <p className="eyebrow">Malleus Studio / local lab</p>
            <h1>Run live attacks and watch the evidence form.</h1>
          </div>
        </header>
        <section className="empty">Loading Studio workspace.</section>
      </main>
    );
  }

  return (
    <main className="shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">Malleus Studio / local lab</p>
          <h1>Show where an AI system bends under attack.</h1>
          <p className="buildMark">Connect a model, launch the showcase benchmark, read the evidence.</p>
        </div>
        <form
          className="apiControl"
          onSubmit={(event) => {
            event.preventDefault();
            setApiBase(apiBaseInput.replace(/\/+$/, ""));
          }}
        >
          <input value={apiBaseInput} onChange={(event) => setApiBaseInput(event.target.value)} />
          <button type="submit">Reconnect</button>
        </form>
      </header>

      {error ? <section className="errorPanel">{error}</section> : null}

      <section className="flowStrip" aria-label="Studio workflow">
        <div className={selectedProviderKey?.present || inferenceReady ? "done" : ""}>
          <span>01</span>
          <strong>Connect</strong>
          <p>{selectedProviderKey?.present ? "Key saved locally" : "Paste a provider key"}</p>
        </div>
        <div className={selectedTarget ? "done" : ""}>
          <span>02</span>
          <strong>Select target</strong>
          <p>{selectedTargetData?.model ?? "Detect models first"}</p>
        </div>
        <div className={scanPlan ? "done" : ""}>
          <span>03</span>
          <strong>Plan</strong>
          <p>{scanPlan ? `${scanPlan.steps.length} attacks ready` : "Build showcase plan"}</p>
        </div>
        <div className={activeRun ? activeRun.status : ""}>
          <span>04</span>
          <strong>Evidence</strong>
          <p>{activeRun ? statusLabel(activeRun.status) : "Run and review findings"}</p>
        </div>
      </section>

      <section className="workbench">
        <aside className="rail">
          <div className="railHeader">
            <span>Attack Library</span>
            <strong>{compatibleAttacks.length}</strong>
          </div>
          {loading ? <SkeletonList /> : null}
          {!loading && compatibleAttacks.length === 0 ? <EmptyState label="No compatible attacks for this target type." /> : null}
          {compatibleAttacks.map((attack) => (
            <button
              className={`attackCard ${selectedAttack === attack.id ? "selected" : ""}`}
              key={attack.id}
              onClick={() => setSelectedAttack(attack.id)}
              type="button"
            >
              <span>{attack.mode}</span>
              <strong>{attack.title}</strong>
              <small>{attack.description}</small>
              <div className="attackMetrics">
                <b>{formatCount(attack.test_count, "test")}</b>
                <b>{formatCount(attack.dataset_count, "dataset")}</b>
                <b>{attack.estimated_cost}</b>
              </div>
              <em>{formatCoverage(attack)}</em>
            </button>
          ))}
        </aside>

        <section className="console">
          <section className="showcaseHero">
            <div>
              <span>Recommended for showcase</span>
              <h2>Findings benchmark</h2>
              <p>Curated for visible failures: prompt boundary, data disclosure, RAG injection, tool injection, memory persistence, and mutation pressure.</p>
            </div>
            <button disabled={!selectedTarget || planningScan || running} onClick={buildScanPlan} type="button">
              {planningScan ? "Planning" : scanPlan ? "Rebuild plan" : "Build showcase"}
            </button>
          </section>
          <div className="providerDock">
            <div className="providerPicker">
              <span>Provider key</span>
              <select value={selectedProvider} onChange={(event) => setSelectedProvider(event.target.value)}>
                {providers
                  .filter((provider) => provider.base_url && provider.api_key_env)
                  .map((provider) => (
                    <option key={provider.id} value={provider.id}>
                      {provider.label}
                    </option>
                  ))}
              </select>
            </div>
            <ProviderLogo provider={selectedProviderData} />
            <label className="keyInput">
              API key
              <input
                autoComplete="off"
                placeholder={selectedProviderData?.api_key_env ?? "API key"}
                type="password"
                value={apiKey}
                onChange={(event) => setApiKey(event.target.value)}
              />
            </label>
            <div className="keyStatus">
              <span className={selectedProviderKey?.present ? "ready" : ""}>
                {selectedProviderKey?.present ? `${selectedProviderKey.source}: ${selectedProviderKey.redacted}` : "No saved key"}
              </span>
              <label className="checkline">
                <input checked={persistKey} onChange={(event) => setPersistKey(event.target.checked)} type="checkbox" />
                Save locally
              </label>
            </div>
            <label className="modelPicker">
              Model
              <select value={selectedModel} onChange={(event) => setSelectedModel(event.target.value)}>
                <option value="">Auto-select first discovered model</option>
                {(models.length ? models : selectedProviderData?.known_models ?? []).map((model) => (
                  <option key={model} value={model}>
                    {model}
                  </option>
                ))}
              </select>
            </label>
            <div className="providerActions">
              <button disabled={(!apiKey && !selectedProviderKey?.present) || discovering} onClick={() => discoverModels()} type="button">
                {discovering ? "Detecting" : "Detect models"}
              </button>
              <button disabled={!apiKey.trim()} onClick={saveProviderKey} type="button">
                Save key
              </button>
              <button disabled={!selectedProviderKey?.present} onClick={deleteProviderKey} type="button">
                Delete key
              </button>
            </div>
            {discoverStatus ? <p>{discoverStatus}</p> : null}
          </div>

          <div className="controlStrip">
            <label>
              Target
          <select value={selectedTarget} onChange={(event) => setSelectedTarget(event.target.value)}>
                {!targets.length ? <option value="">No targets yet</option> : null}
                {targets.map((target) => (
                  <option key={target.id} value={target.id}>
                    {target.name} / {target.target_type}{target.source === "studio-wrapper" ? " / auto-wrapper" : ""}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Timeout
              <input min="10" step="10" type="number" value={requestTimeout} onChange={(event) => setRequestTimeout(Number(event.target.value))} />
            </label>
            <label>
              Retries
              <input min="0" max="5" type="number" value={maxRetries} onChange={(event) => setMaxRetries(Number(event.target.value))} />
            </label>
            <button disabled={!selectedTarget || !selectedAttack || running} onClick={startRun} type="button">
              {running ? "Running" : "Run attack"}
            </button>
          </div>

          <section className="scanBuilder">
            <div className="scanBuilderHeader">
              <div>
                <h2>Benchmark plan</h2>
                <p>Use the showcase profile for demos; switch profile only when you need a different depth.</p>
              </div>
              <button disabled={!selectedTarget || planningScan} onClick={buildScanPlan} type="button">
                {planningScan ? "Planning" : "Build plan"}
              </button>
            </div>
            <div className="scanControls">
              <label>
                Profile
                <select value={selectedScanProfile} onChange={(event) => setSelectedScanProfile(event.target.value)}>
                  {scanProfiles.map((profile) => (
                    <option key={profile.id} value={profile.id}>
                      {profile.title}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Languages
                <input value={scanLanguages} onChange={(event) => setScanLanguages(event.target.value)} />
              </label>
              <label>
                Budget
                <input min="0" placeholder="all" type="number" value={scanBudget} onChange={(event) => setScanBudget(event.target.value)} />
              </label>
              <label>
                Seed
                <input type="number" value={scanSeed} onChange={(event) => setScanSeed(Number(event.target.value))} />
              </label>
            </div>
            <label className="scanDescription">
              Agent description
              <textarea
                placeholder="Public demo agent with RAG, tools, memory, and customer-account boundaries."
                value={scanDescription}
                onChange={(event) => setScanDescription(event.target.value)}
              />
            </label>
            {scanPlan ? (
              <ScanPlanPreview
                disabled={!selectedTarget || running}
                onRunPlan={startScanRun}
                onSelectAttack={setSelectedAttack}
                plan={scanPlan}
                selectedAttack={selectedAttack}
              />
            ) : null}
          </section>

          <div className="brief">
            <div>
              <span>Selected attack</span>
              <strong>{selectedAttackData?.title ?? "No attack selected"}</strong>
              <p>{selectedAttackData?.description ?? "Start the Studio API to load attacks."}</p>
            </div>
            <div>
              <span>Target</span>
              <strong>{selectedTargetData?.name ?? "No target"}</strong>
              <p>{selectedTargetData?.model ?? selectedTargetData?.path ?? "Paste a provider key, detect models, then Studio will create a local target."}</p>
              {selectedTargetData?.source === "studio-wrapper" ? <em className="wrapperNotice">auto-wrapper over {String(selectedTargetData.config?.model ?? "base model")}</em> : null}
            </div>
          </div>

          <div className="liveHeader">
            <h2>Evidence Stream</h2>
            <div className="liveActions">
              <span>{activeRun?.status ?? "idle"}</span>
              {activeRun && ["queued", "running"].includes(activeRun.status) ? (
                <button onClick={cancelRun} type="button">
                  Cancel run
                </button>
              ) : null}
            </div>
          </div>
          <div className="eventStream">
            {!activeRun && !events.length ? <EmptyState label="Start a run to stream case, row, checkpoint, and result events." /> : null}
            {activeRun ? <RunProgressPanel progress={progress} run={activeRun} /> : null}
            {caseCards.map((card) => (
              <CaseReplayCard card={card} key={card.caseId} />
            ))}
            {surfaceCards.map((card) => (
              <SurfaceEvidenceCard card={card} key={`${card.dataset}:${card.caseId}`} />
            ))}
            {technicalEvents.length ? <TechnicalTimeline events={technicalEvents} /> : null}
          </div>
        </section>

        <aside className="detail">
          <h2>Run Detail</h2>
          {!activeRun ? <EmptyState label="No active run yet." /> : <RunDetail apiBase={apiBase} artifacts={activeHistoryItem?.artifacts ?? []} run={activeRun} />}
          <RunHistory
            apiBase={apiBase}
            currentRunId={activeRun?.run_id}
            items={runHistory}
            onSelect={(item) => {
              loadRunFromHistory(item);
            }}
          />
        </aside>
      </section>
    </main>
  );
}

async function loadStudioCatalog(preferredBase: string) {
  const candidates = [preferredBase, ...DEFAULT_API_BASES].map((value) => value.replace(/\/+$/, ""));
  const uniqueCandidates = Array.from(new Set(candidates));
  const errors: string[] = [];
  for (const base of uniqueCandidates) {
    try {
      const [targetResponse, attackResponse, scanProfileResponse, providerResponse, providerKeyResponse, historyResponse] = await Promise.all([
        fetch(`${base}/api/targets`),
        fetch(`${base}/api/attacks`),
        fetch(`${base}/api/scan-profiles`),
        fetch(`${base}/api/providers`),
        fetch(`${base}/api/provider-keys`),
        fetch(`${base}/api/run-history`)
      ]);
      if (
        targetResponse.ok &&
        attackResponse.ok &&
        scanProfileResponse.ok &&
        providerResponse.ok &&
        providerKeyResponse.ok &&
        historyResponse.ok
      ) {
        return {
          base,
          targetData: await targetResponse.json(),
          attackData: await attackResponse.json(),
          scanProfileData: await scanProfileResponse.json(),
          providerData: await providerResponse.json(),
          providerKeyData: await providerKeyResponse.json(),
          historyData: await historyResponse.json()
        };
      }
      errors.push(
        `${base} returned targets=${targetResponse.status} attacks=${attackResponse.status} scanProfiles=${scanProfileResponse.status} providers=${providerResponse.status} keys=${providerKeyResponse.status} history=${historyResponse.status}`
      );
    } catch (error) {
      errors.push(`${base} unreachable: ${error instanceof Error ? error.message : "request failed"}`);
    }
  }
  throw new Error(`Studio API not ready. ${errors.join(" | ")}`);
}

function ProviderLogo({ provider }: { provider?: StudioProvider }) {
  if (!provider?.logo_svg) return <div className="providerLogo emptyLogo" />;
  return <div className="providerLogo" dangerouslySetInnerHTML={{ __html: provider.logo_svg }} />;
}

function ScanPlanPreview({
  disabled,
  onRunPlan,
  onSelectAttack,
  plan,
  selectedAttack
}: {
  disabled: boolean;
  onRunPlan: () => void;
  onSelectAttack: (attackId: string) => void;
  plan: StudioScanPlan;
  selectedAttack: string;
}) {
  return (
    <div className="scanPlan">
      <div className="scanPlanSummary">
        <strong>{plan.profile.title}</strong>
        <span>{plan.steps.length} attacks</span>
        <span>{plan.total_tests ?? "--"} tests</span>
        <span>{plan.estimated_cost}</span>
      </div>
      <button className="runPlanButton" disabled={disabled || !plan.steps.length} onClick={onRunPlan} type="button">
        Run plan
      </button>
      <div className="threatGroups">
        {Object.entries(plan.threat_groups).map(([name, count]) => (
          <span key={name}>
            {name}: {count}
          </span>
        ))}
      </div>
      <div className="scanSteps">
        {plan.steps.map((step) => (
          <button
            className={selectedAttack === step.attack_id ? "selected" : ""}
            key={`${step.sequence}-${step.attack_id}`}
            onClick={() => onSelectAttack(step.attack_id)}
            type="button"
          >
            <span>{step.sequence.toString().padStart(2, "0")}</span>
            <strong>{step.title}</strong>
            <small>{step.test_count ?? "--"} tests / {step.estimated_cost}</small>
          </button>
        ))}
      </div>
    </div>
  );
}

function formatCount(value: number | null | undefined, label: string) {
  if (!value) return `-- ${label}s`;
  return `${value} ${label}${value === 1 ? "" : "s"}`;
}

function formatCoverage(attack: StudioAttack) {
  const coverage = attack.coverage?.slice(0, 2) ?? [];
  if (coverage.length) return coverage.join(" / ");
  return attack.surface;
}

type CaseReplay = {
  caseId: string;
  dataset: string;
  objective: string;
  prompt: string;
  status: "running" | "passed" | "review";
  score?: string;
  response?: string;
  checks: string[];
  raw: StudioEvent[];
};

type SurfaceEvidence = {
  caseId: string;
  dataset: string;
  objective: string;
  status: string;
  reason: string;
  reasonCodes: string[];
  evidenceFidelity: string;
  response: string;
  traceSummary: Record<string, unknown>;
  surfaceKind: "rag" | "tool" | "workflow" | "memory" | "browser" | "code" | "system";
  raw: StudioEvent;
};

type RunProgress = {
  completedRows: number;
  totalRows: number | null;
  activeRow: string;
  rows: Array<{ id: string; name: string; status: string }>;
};

function buildRunProgress(events: StudioEvent[]): RunProgress {
  const rows = new Map<string, { id: string; name: string; status: string }>();
  let completedRows = 0;
  let totalRows: number | null = null;
  let activeRow = "";

  for (const event of events) {
    const payload = event.payload;
    if (event.event === "run_start" && typeof payload.total_rows === "number") {
      totalRows = payload.total_rows;
    }
    if (event.event === "checkpoint") {
      if (typeof payload.completed_rows === "number") completedRows = payload.completed_rows;
      if (typeof payload.total_rows === "number") totalRows = payload.total_rows;
    }
    if (event.event === "row_start" || event.event === "row_end") {
      const id = String(payload.row_id ?? payload.surface_id ?? `row-${event.sequence}`);
      const name = String(payload.surface_name ?? payload.surface_id ?? id);
      const status = event.event === "row_start" ? "running" : String(payload.status ?? "completed");
      rows.set(id, { id, name, status });
      if (event.event === "row_start") activeRow = name;
      if (event.event === "row_end" && activeRow === name) activeRow = "";
    }
    if (event.event === "scan_started" && typeof payload.step_count === "number") {
      totalRows = payload.step_count;
      completedRows = 0;
      activeRow = "Scan campaign";
    }
    if (event.event === "scan_step_started" || event.event === "scan_step_completed") {
      const id = String(payload.attack_id ?? `step-${event.sequence}`);
      const title = String(payload.title ?? payload.attack_id ?? id);
      const status = event.event === "scan_step_started" ? "running" : "completed";
      rows.set(id, { id, name: title, status });
      if (event.event === "scan_step_started") activeRow = title;
      if (event.event === "scan_step_completed") {
        completedRows += 1;
        if (activeRow === title) activeRow = "";
      }
    }
  }

  return { completedRows, totalRows, activeRow, rows: Array.from(rows.values()) };
}

function buildCaseCards(events: StudioEvent[]): CaseReplay[] {
  const cards = new Map<string, CaseReplay>();
  for (const event of events) {
    if (!["case_start", "case_end"].includes(event.event)) continue;
    const caseId = String(event.payload.case_id ?? "case");
    const dataset = String(event.payload.dataset ?? "dataset");
    const key = `${dataset}:${caseId}`;
    const current =
      cards.get(key) ??
      ({
        caseId,
        dataset,
        objective: "",
        prompt: "",
        status: "running",
        checks: [],
        raw: []
      } satisfies CaseReplay);
    current.raw.push(event);
    if (event.event === "case_start") {
      current.objective = String(event.payload.objective ?? "");
      current.prompt = String(event.payload.prompt ?? "");
      current.status = "running";
    }
    if (event.event === "case_end") {
      current.status = event.payload.passed === true ? "passed" : "review";
      current.score =
        event.payload.score !== undefined ? `${String(event.payload.score)}/${String(event.payload.max_score ?? "")}` : undefined;
      current.response = String(event.payload.response ?? "");
      current.checks = Array.isArray(event.payload.failure_checks)
        ? event.payload.failure_checks.map((item) => String(item))
        : [];
    }
    cards.set(key, current);
  }
  return Array.from(cards.values());
}

function buildSurfaceEvidenceCards(events: StudioEvent[]): SurfaceEvidence[] {
  return events
    .filter((event) => event.event === "system_case_end")
    .map((event) => {
      const payload = event.payload;
      const evidenceFidelity = String(payload.evidence_fidelity ?? "");
      const traceSummary = isRecord(payload.trace_summary) ? payload.trace_summary : {};
      return {
        caseId: String(payload.case_id ?? "system-case"),
        dataset: String(payload.dataset ?? "system-surface"),
        objective: String(payload.objective ?? ""),
        status: String(payload.status ?? "unknown"),
        reason: String(payload.reason ?? ""),
        reasonCodes: Array.isArray(payload.reason_codes) ? payload.reason_codes.map((item) => String(item)) : [],
        evidenceFidelity,
        response: String(payload.response ?? ""),
        traceSummary,
        surfaceKind: surfaceKindFromFidelity(evidenceFidelity),
        raw: event
      } satisfies SurfaceEvidence;
    });
}

function CaseReplayCard({ card }: { card: CaseReplay }) {
  return (
    <article className={`caseCard ${card.status}`}>
      <div className="caseTopline">
        <span>{card.dataset}</span>
        <strong>{card.caseId}</strong>
        <b>{card.status === "passed" ? "Passed" : card.status === "running" ? "Running" : "Needs review"}</b>
      </div>
      <div className="caseBody">
        <section>
          <h4>What Malleus asked</h4>
          <p>{card.objective || "Waiting for the test objective."}</p>
          {card.prompt ? <blockquote>{card.prompt}</blockquote> : null}
        </section>
        <section>
          <h4>How the model answered</h4>
          <p className="answerPreview">{card.response || "Waiting for the model response."}</p>
          {card.score ? <span className="scorePill">Score {card.score}</span> : null}
        </section>
      </div>
      {card.response ? (
        <details className="fullResponse">
          <summary>Full model response</summary>
          <pre>{card.response}</pre>
        </details>
      ) : null}
      {card.checks.length ? (
        <div className="reviewBox">
          <h4>Why this needs review</h4>
          {card.checks.map((check, index) => (
            <p key={`${card.caseId}-check-${index}`}>{humanizeCheck(check)}</p>
          ))}
        </div>
      ) : null}
      <details>
        <summary>Technical event data</summary>
        <pre>{JSON.stringify(card.raw.map((event) => event.payload), null, 2)}</pre>
      </details>
    </article>
  );
}

function SurfaceEvidenceCard({ card }: { card: SurfaceEvidence }) {
  const status = normalizedSurfaceStatus(card.status);
  const labels = surfaceLabels(card.surfaceKind);
  const traceItems = surfaceTraceItems(card);
  const primaryLists = surfacePrimaryLists(card);

  return (
    <article className={`surfaceCard ${status}`}>
      <div className="surfaceTopline">
        <div>
          <span>{labels.kicker}</span>
          <strong>{card.caseId}</strong>
        </div>
        <b>{statusLabelForSurface(card.status)}</b>
      </div>
      <div className="surfaceBody">
        <section>
          <h4>{labels.objective}</h4>
          <p>{card.objective || "No objective captured for this surface."}</p>
          {card.reason ? <blockquote>{card.reason}</blockquote> : null}
        </section>
        <section>
          <h4>{labels.output}</h4>
          <p className="answerPreview">{card.response || "No response excerpt captured."}</p>
          <span className="fidelityPill">{card.evidenceFidelity || "unknown fidelity"}</span>
        </section>
      </div>
      {traceItems.length ? (
        <div className="traceGrid">
          {traceItems.map((item) => (
            <div key={item.label}>
              <span>{item.label}</span>
              <strong>{item.value}</strong>
            </div>
          ))}
        </div>
      ) : null}
      {primaryLists.map((list) => (
        <EvidenceList items={list.items} key={list.label} label={list.label} />
      ))}
      {card.reasonCodes.length ? (
        <div className="reasonCodes">
          {card.reasonCodes.map((code) => (
            <span key={code}>{code}</span>
          ))}
        </div>
      ) : null}
      <SurfaceArtifacts payload={card.raw.payload} />
      <details>
        <summary>Technical evidence payload</summary>
        <pre>{JSON.stringify(card.raw.payload, null, 2)}</pre>
      </details>
    </article>
  );
}

function SurfaceArtifacts({ payload }: { payload: Record<string, unknown> }) {
  const evidenceRef = typeof payload.evidence_ref === "string" ? payload.evidence_ref : "";
  const artifacts = Array.isArray(payload.artifact_refs)
    ? payload.artifact_refs
        .map((item) => (isRecord(item) ? String(item.path ?? item.relative_path ?? "") : String(item)))
        .filter(Boolean)
        .slice(0, 6)
    : [];
  if (!evidenceRef && !artifacts.length) return null;
  return (
    <div className="surfaceArtifacts">
      {evidenceRef ? (
        <p>
          <span>evidence</span>
          {evidenceRef}
        </p>
      ) : null}
      {artifacts.map((artifact) => (
        <p key={artifact}>
          <span>artifact</span>
          {artifact}
        </p>
      ))}
    </div>
  );
}

function EvidenceList({ label, items }: { label: string; items: string[] }) {
  if (!items.length) return null;
  return (
    <div className="evidenceList">
      <h4>{label}</h4>
      <div>
        {items.map((item) => (
          <span key={item}>{item}</span>
        ))}
      </div>
    </div>
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function surfaceKindFromFidelity(fidelity: string): SurfaceEvidence["surfaceKind"] {
  const normalized = fidelity.toLowerCase();
  if (normalized.includes("rag")) return "rag";
  if (normalized.includes("tool")) return "tool";
  if (normalized.includes("workflow")) return "workflow";
  if (normalized.includes("memory")) return "memory";
  if (normalized.includes("browser")) return "browser";
  if (normalized.includes("code")) return "code";
  return "system";
}

function normalizedSurfaceStatus(status: string) {
  const normalized = status.toLowerCase();
  if (["passed", "completed", "ok"].includes(normalized)) return "passed";
  if (["failed", "error", "target_error", "infra_error"].includes(normalized)) return "failed";
  return "review";
}

function statusLabelForSurface(status: string) {
  const normalized = normalizedSurfaceStatus(status);
  if (normalized === "passed") return "Passed";
  if (normalized === "failed") return "Failed";
  return "Review";
}

function surfaceLabels(kind: SurfaceEvidence["surfaceKind"]) {
  if (kind === "rag") return { kicker: "RAG evidence", objective: "Query / objective", output: "Answer and citations" };
  if (kind === "tool") return { kicker: "Tool trace", objective: "Agent objective", output: "Final answer" };
  if (kind === "workflow") return { kicker: "Workflow evidence", objective: "Workflow objective", output: "Workflow result" };
  if (kind === "memory") return { kicker: "Memory evidence", objective: "Memory probe", output: "Model output" };
  if (kind === "browser") return { kicker: "Browser evidence", objective: "Browser objective", output: "DOM / final state" };
  if (kind === "code") return { kicker: "Workspace evidence", objective: "Code task", output: "Execution output" };
  return { kicker: "System evidence", objective: "Objective", output: "Observed output" };
}

function numberFromTrace(trace: Record<string, unknown>, key: string) {
  const value = trace[key];
  return typeof value === "number" ? value : 0;
}

function stringArrayFromTrace(trace: Record<string, unknown>, key: string) {
  const value = trace[key];
  if (!Array.isArray(value)) return [];
  return value.map((item) => String(item)).filter(Boolean);
}

function surfaceTraceItems(card: SurfaceEvidence) {
  const trace = card.traceSummary;
  const base = [
    { label: "target calls", value: numberFromTrace(trace, "target_call_count") },
    { label: "traces", value: numberFromTrace(trace, "target_trace_count") }
  ];
  if (card.surfaceKind === "rag") {
    return [
      ...base,
      { label: "retrieved", value: stringArrayFromTrace(trace, "retrieved_ids").length },
      { label: "cited", value: stringArrayFromTrace(trace, "cited_ids").length }
    ];
  }
  if (card.surfaceKind === "code") {
    return [
      ...base,
      { label: "files changed", value: stringArrayFromTrace(trace, "changed_files").length },
      { label: "blocked ops", value: numberFromTrace(trace, "blocked_operation_count") || numberFromTrace(trace, "blocked_operations") }
    ];
  }
  return [
    ...base,
    { label: "tool calls", value: numberFromTrace(trace, "tool_call_count") || numberFromTrace(trace, "tool_calls") },
    { label: "actions", value: numberFromTrace(trace, "action_count") || numberFromTrace(trace, "actions") },
    { label: "blocked ops", value: numberFromTrace(trace, "blocked_operation_count") || numberFromTrace(trace, "blocked_operations") }
  ];
}

function surfacePrimaryLists(card: SurfaceEvidence) {
  const trace = card.traceSummary;
  if (card.surfaceKind === "rag") {
    return [
      { label: "Retrieved documents", items: stringArrayFromTrace(trace, "retrieved_ids") },
      { label: "Cited documents", items: stringArrayFromTrace(trace, "cited_ids") }
    ];
  }
  if (card.surfaceKind === "code") {
    return [
      { label: "Changed files", items: stringArrayFromTrace(trace, "changed_files") },
      { label: "Blocked operations", items: stringArrayFromTrace(trace, "blocked_operation_names") }
    ];
  }
  return [
    { label: "Tool calls", items: stringArrayFromTrace(trace, "tool_call_names") },
    { label: "Actions", items: stringArrayFromTrace(trace, "action_names") },
    { label: "Blocked operations", items: stringArrayFromTrace(trace, "blocked_operation_names") }
  ];
}

function RunProgressPanel({ progress, run }: { progress: RunProgress; run: StudioRun }) {
  const total = progress.totalRows ?? progress.rows.length;
  const hasRows = total > 0;
  const percent = hasRows ? Math.min(100, Math.round((progress.completedRows / total) * 100)) : run.status === "completed" ? 100 : 0;
  const itemSummary =
    run.total_items > 0 ? `${run.passed_items}/${run.total_items} tests` : run.score ? `Score ${run.score}` : "Waiting for result summary";

  return (
    <section className={`runProgress ${hasRows ? "" : "summaryOnly"}`}>
      <div>
        <span>{hasRows ? "Run progress" : "Run status"}</span>
        <strong>{progress.activeRow || statusLabel(run.status)}</strong>
      </div>
      <b>{hasRows ? `${progress.completedRows}/${total} rows` : itemSummary}</b>
      {hasRows ? (
        <div className="progressTrack">
          <i style={{ width: `${percent}%` }} />
        </div>
      ) : null}
      {progress.rows.length ? (
        <div className="surfaceRail">
          {progress.rows.slice(-6).map((row) => (
            <span className={`surfaceStatus ${row.status}`} key={row.id}>
              {row.name}
            </span>
          ))}
        </div>
      ) : null}
    </section>
  );
}

function statusLabel(status: StudioRun["status"]) {
  if (status === "running") return "Running selected benchmark";
  if (status === "queued") return "Queued";
  if (status === "completed") return "Completed";
  if (status === "cancelled") return "Cancelled";
  return "Failed";
}

function TechnicalTimeline({ events }: { events: StudioEvent[] }) {
  const counts = events.reduce<Record<string, number>>((accumulator, event) => {
    accumulator[event.event] = (accumulator[event.event] ?? 0) + 1;
    return accumulator;
  }, {});
  const latest = events.at(-1);

  return (
    <details className="technicalTimeline">
      <summary>
        <span>Technical timeline</span>
        {latest ? <b>latest {latest.sequence.toString().padStart(3, "0")}</b> : null}
      </summary>
      <div className="technicalStats">
        {Object.entries(counts).map(([eventName, count]) => (
          <span key={eventName}>
            {eventName}: {count}
          </span>
        ))}
      </div>
      {events.slice(-12).map((event) => (
        <SystemEvent event={event} key={event.sequence} />
      ))}
    </details>
  );
}

function SystemEvent({ event }: { event: StudioEvent }) {
  return (
    <article className="systemEvent">
      <span>{event.sequence.toString().padStart(3, "0")}</span>
      <strong className={`eventName ${event.event}`}>{event.event}</strong>
      <b>{eventSummary(event)}</b>
    </article>
  );
}

function humanizeCheck(check: string) {
  return check
    .replace(/^label=[^;]+;\s*/i, "")
    .replace(/substring did not match:/gi, "The answer did not contain the expected safe marker:")
    .replace(/unsafe phrase did not match:/gi, "The unsafe phrase was not detected:")
    .replace(/refusal marker did not match:/gi, "The response did not look like a refusal:");
}

function RunDetail({ apiBase, artifacts, run }: { apiBase: string; artifacts: RunArtifact[]; run: StudioRun }) {
  return (
    <div className="runDetail">
      <div className="detailHero">
        <div className={`status ${run.status}`}>{run.status}</div>
        <strong>{run.score ?? "pending"}</strong>
        <span>
          {run.passed_items}/{run.total_items} items
        </span>
      </div>
      <div className="runtimeBadges">
        {run.provider_in_flight ? <span className="hot">provider call in-flight</span> : <span>provider idle</span>}
        {run.request_timeout ? <span>timeout {run.request_timeout}s</span> : null}
        {run.max_retries !== undefined && run.max_retries !== null ? <span>{run.max_retries} retries</span> : null}
        {run.cancel_requested ? <span className="warn">stop requested</span> : null}
        {run.terminal_reason ? <span>{run.terminal_reason}</span> : null}
      </div>
      <dl>
        <div>
          <dt>Run</dt>
          <dd>{run.run_id}</dd>
        </div>
        <div>
          <dt>Output</dt>
          <dd>{run.out_dir}</dd>
        </div>
      </dl>
      <div className="exportLinks">
        <a href={runExportUrl(apiBase, run.run_id, "html")} target="_blank" rel="noreferrer">
          Export HTML
        </a>
        <a href={runExportUrl(apiBase, run.run_id, "json")} target="_blank" rel="noreferrer">
          Export JSON
        </a>
      </div>
      {run.report_json ? <p className="artifact"><span>report</span>{run.report_json}</p> : null}
      {run.evidence_json ? <p className="artifact"><span>evidence</span>{run.evidence_json}</p> : null}
      {artifacts.length ? (
        <div className="artifactLinks">
          <h3>Artifacts</h3>
          {artifacts.slice(0, 10).map((artifact) => (
            <a href={artifactUrl(apiBase, run.run_id, artifact.path)} key={artifact.path} target="_blank" rel="noreferrer">
              <span>{artifact.kind}</span>
              {artifact.path}
            </a>
          ))}
        </div>
      ) : null}
      {run.error ? <p className="errorText">{run.error}</p> : null}
      <h3>Findings</h3>
      {run.failed_cases.length === 0 ? <p className="muted">No findings recorded yet. Passed runs still export full evidence.</p> : null}
      {run.failed_cases.map((item, index) => (
        <article className="failedCase" key={`${String(item.case_id)}-${index}`}>
          <strong>{String(item.case_id ?? "unknown")}</strong>
          <span>{String(item.dataset ?? "")}</span>
          <p>{String(item.reason ?? item.excerpt ?? "No redacted detail.")}</p>
        </article>
      ))}
    </div>
  );
}

function RunHistory({
  currentRunId,
  items,
  onSelect
}: {
  apiBase: string;
  currentRunId?: string;
  items: RunHistoryItem[];
  onSelect: (item: RunHistoryItem) => void;
}) {
  return (
    <section className="historyPanel">
      <div className="historyHeader">
        <h2>Run History</h2>
        <strong>{items.length}</strong>
      </div>
      {!items.length ? <p className="muted">No saved Studio runs yet.</p> : null}
      {items.slice(0, 8).map((item) => (
        <button
          className={`historyItem ${currentRunId === item.run.run_id ? "selected" : ""}`}
          key={item.run.run_id}
          onClick={() => onSelect(item)}
          type="button"
        >
          <span>{item.run.status}</span>
          <strong>{item.run.attack_id}</strong>
          <small>{item.run.target}</small>
          <b>{item.run.provider_in_flight ? "in-flight" : item.run.score ?? `${item.event_count} events`}</b>
        </button>
      ))}
    </section>
  );
}

function artifactUrl(apiBase: string, runId: string, path: string) {
  return `${apiBase}/api/runs/${encodeURIComponent(runId)}/artifact?path=${encodeURIComponent(path)}`;
}

function runExportUrl(apiBase: string, runId: string, format: "html" | "json") {
  return `${apiBase}/api/runs/${encodeURIComponent(runId)}/export.${format}`;
}

function eventSummary(event: StudioEvent) {
  const payload = event.payload;
  if (event.event === "queued") return `${String(payload.attack_id ?? "attack")} queued`;
  if (event.event === "run_started") return "Run started";
  if (event.event === "run_completed") return "Run completed";
  if (event.event === "run_failed") return String(payload.error ?? "Run failed");
  if (event.event === "case_start") {
    return `${String(payload.dataset ?? "dataset")} / ${String(payload.case_id ?? "case")}`;
  }
  if (event.event === "case_end") {
    const status = payload.passed === true ? "passed" : "review";
    const score = payload.score !== undefined ? `score ${String(payload.score)}/${String(payload.max_score ?? "")}` : "";
    return `${String(payload.dataset ?? "dataset")} / ${String(payload.case_id ?? "case")} ${status} ${score}`.trim();
  }
  if (event.event === "row_start" || event.event === "row_end") {
    return `${String(payload.surface_name ?? payload.surface_id ?? "surface")} ${String(payload.status ?? "")}`.trim();
  }
  if (event.event === "checkpoint") {
    return `${String(payload.completed_rows ?? "0")}/${String(payload.total_rows ?? "?")} rows checkpointed`;
  }
  if (event.event === "preflight_start") return "Target preflight started";
  if (event.event === "preflight_end") {
    return `Text ${payload.text_ready === true ? "ready" : "not ready"} / ${String(payload.text_status ?? "unknown")}`;
  }
  return Object.keys(payload).slice(0, 3).join(" / ") || event.event;
}

function SkeletonList() {
  return (
    <div className="skeletonList">
      <span />
      <span />
      <span />
    </div>
  );
}

function EmptyState({ label }: { label: string }) {
  return <div className="empty">{label}</div>;
}
