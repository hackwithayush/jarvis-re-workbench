// JARVIS RE Workbench v1.0 — Frontend Controller

let currentReport = null;
let selectedFunction = null;

document.addEventListener("DOMContentLoaded", () => {
  initUpload();
  initTabs();
  initVoice();
  initFilters();
  loadTools();
});

function initUpload() {
  const dropZone = document.getElementById("dropZone");
  const fileInput = document.getElementById("fileInput");

  dropZone.addEventListener("click", () => fileInput.click());

  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("dragover");
  });

  dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("dragover");
  });

  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) {
      uploadFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0) {
      uploadFile(fileInput.files[0]);
    }
  });
}

async function uploadFile(file) {
  const progressBox = document.getElementById("progressBox");
  const progressBar = document.getElementById("progressBar");
  const progressText = document.getElementById("progressText");
  const resultsSection = document.getElementById("resultsSection");

  progressBox.style.display = "block";
  resultsSection.style.display = "none";
  progressBar.style.width = "20%";
  progressText.textContent = `Uploading ${file.name} to background analysis pipeline...`;

  const formData = new FormData();
  formData.append("file", file);

  try {
    // 1. Submit async job
    progressBar.style.width = "35%";
    progressText.textContent = "Multi-engine analysis started (PE/ELF headers, entropy, strings)...";

    const response = await fetch("/api/jobs", {
      method: "POST",
      body: formData,
    });

    if (!response.ok) {
      // Fallback to synchronous /api/analyze if needed
      return await fallbackSyncAnalyze(formData);
    }

    const job = await response.json();
    pollJob(job.job_id);

  } catch (error) {
    console.warn("Async job submission error, attempting direct analysis:", error);
    await fallbackSyncAnalyze(formData);
  }
}

async function fallbackSyncAnalyze(formData) {
  const progressBox = document.getElementById("progressBox");
  const progressBar = document.getElementById("progressBar");
  const progressText = document.getElementById("progressText");

  try {
    progressBar.style.width = "60%";
    progressText.textContent = "Analyzing executable structures, signatures, and functions...";

    const res = await fetch("/api/analyze", {
      method: "POST",
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Analysis failed");
    }
    currentReport = await res.json();
    progressBar.style.width = "100%";
    progressText.textContent = "Analysis complete! Rendering technical report...";
    setTimeout(() => {
      progressBox.style.display = "none";
      renderReport(currentReport);
    }, 400);
  } catch (e) {
    progressBox.style.display = "none";
    alert(`Analysis error: ${e.message}`);
  }
}

function pollJob(jobId) {
  const progressBar = document.getElementById("progressBar");
  const progressText = document.getElementById("progressText");
  const progressBox = document.getElementById("progressBox");
  const jobLog = document.getElementById("jobLog");

  const interval = setInterval(async () => {
    try {
      const res = await fetch(`/api/jobs/${jobId}`);
      if (!res.ok) return;
      const job = await res.json();

      progressBar.style.width = `${job.progress_pct}%`;
      progressText.textContent = job.current_stage;
      if (job.logs && job.logs.length > 0) {
        jobLog.textContent = job.logs[job.logs.length - 1];
      }

      if (job.status === "completed") {
        clearInterval(interval);
        currentReport = job.report;
        setTimeout(() => {
          progressBox.style.display = "none";
          renderReport(currentReport);
        }, 400);
      } else if (job.status === "failed") {
        clearInterval(interval);
        progressBox.style.display = "none";
        alert(`Analysis failed: ${job.error}`);
      }
    } catch (e) {
      console.error("Polling error:", e);
    }
  }, 1000);
}

function renderReport(report) {
  const resultsSection = document.getElementById("resultsSection");
  resultsSection.style.display = "block";

  const s = report.sample;
  const sum = report.summary || {};

  // Metadata cards
  document.getElementById("metaFilename").textContent = s.filename || "—";
  document.getElementById("metaFormat").textContent = s.file_type || "—";
  document.getElementById("metaArch").textContent = s.architecture || "—";
  document.getElementById("metaSize").textContent = `${(s.file_size || 0).toLocaleString()} bytes`;
  document.getElementById("metaEntropy").textContent = `${s.entropy} / 8.000`;
  document.getElementById("metaImphash").textContent = s.imphash || "N/A";
  document.getElementById("metaSha256").textContent = s.sha256 || "—";

  // 1. Findings Table
  renderFindings(report.findings || []);

  // 2. Sections Table
  renderSections(report.sections || []);

  // 3. Imports & Exports
  renderImportsAndExports(report.imports || [], report.exports || []);

  // 4. Functions & Disassembly
  renderFunctions(report.functions || []);

  // 5. CFG
  if (report.functions && report.functions.length > 0) {
    selectFunction(report.functions[0]);
  }

  // 6. AI Analyst
  renderAIAnalyst(report);

  // 7. Raw JSON
  document.getElementById("rawJson").textContent = JSON.stringify(report, null, 2);
}

function renderFindings(findings) {
  const tbody = document.getElementById("findingsTableBody");
  tbody.innerHTML = "";

  findings.forEach((f) => {
    const tr = document.createElement("tr");
    tr.dataset.type = f.finding_type || "other";

    const confPct = Math.round((f.confidence || 0) * 100);
    const badgeClass = confPct >= 80 ? "badge-success" : (confPct >= 60 ? "badge-warning" : "badge-info");

    tr.innerHTML = `
      <td><code>${escapeHtml(f.address_or_location || "N/A")}</code></td>
      <td><span class="badge ${badgeClass}">${escapeHtml(f.finding_type)}</span></td>
      <td><strong>${escapeHtml(f.name)}</strong></td>
      <td><code>${escapeHtml(f.source_tool || "builtin")}</code></td>
      <td><span class="badge ${badgeClass}">${confPct}%</span></td>
      <td style="font-size: 12px; color: #b8c4e0;">${escapeHtml(f.description)}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderSections(sections) {
  const tbody = document.getElementById("sectionsTableBody");
  tbody.innerHTML = "";

  if (sections.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No section headers present.</td></tr>`;
    return;
  }

  sections.forEach((sec) => {
    const tr = document.createElement("tr");
    const entropyBadge = sec.entropy > 7.1 ? '<span class="badge badge-danger">High (Packed)</span>' : '<span class="badge badge-success">Normal</span>';

    tr.innerHTML = `
      <td><strong>${escapeHtml(sec.name)}</strong></td>
      <td><code>${escapeHtml(sec.virtual_address)}</code></td>
      <td>${sec.virtual_size.toLocaleString()} B</td>
      <td>${sec.raw_size.toLocaleString()} B</td>
      <td><code>${sec.entropy.toFixed(2)}</code> ${entropyBadge}</td>
      <td style="font-size: 11px; color: var(--text-muted);">${escapeHtml((sec.flags || []).join(", ") || "None")}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderImportsAndExports(imports, exports) {
  const container = document.getElementById("importsContainer");
  container.innerHTML = "";

  if (imports.length === 0) {
    container.innerHTML = `<p style="color: var(--text-muted); font-size: 13px;">No import table symbols detected.</p>`;
  } else {
    imports.forEach((mod) => {
      const card = document.createElement("div");
      card.style.cssText = "background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 12px; margin-bottom: 12px;";

      const suspCount = mod.functions.filter(f => f.is_suspicious).length;
      card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <strong style="color: var(--accent); font-size: 13px;">${escapeHtml(mod.module_name)}</strong>
          <span style="font-size: 11px; color: var(--text-muted);">${mod.functions.length} function(s) ${suspCount > 0 ? `<span class="badge badge-danger">${suspCount} Suspicious</span>` : ''}</span>
        </div>
        <div style="display: flex; flex-wrap: wrap; gap: 6px;">
          ${mod.functions.map(fn => `
            <span class="badge ${fn.is_suspicious ? 'badge-danger' : 'badge-info'}" title="${escapeHtml(fn.category || '')}">
              ${escapeHtml(fn.name)}
            </span>
          `).join("")}
        </div>
      `;
      container.appendChild(card);
    });
  }

  // Exports table
  const expTbody = document.getElementById("exportsTableBody");
  expTbody.innerHTML = "";
  if (exports.length === 0) {
    expTbody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-muted);">No exported symbols.</td></tr>`;
  } else {
    exports.forEach((e) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><code>${e.ordinal}</code></td>
        <td><strong>${escapeHtml(e.name || "N/A")}</strong></td>
        <td><code>${escapeHtml(e.rva)}</code></td>
      `;
      expTbody.appendChild(tr);
    });
  }
}

function renderFunctions(functions) {
  const list = document.getElementById("functionList");
  list.innerHTML = "";

  if (functions.length === 0) {
    list.innerHTML = `<div style="padding: 12px; color: var(--text-muted); font-size: 12px;">No recovered functions.</div>`;
    return;
  }

  functions.forEach((f, idx) => {
    const item = document.createElement("div");
    item.style.cssText = "padding: 8px 12px; border-bottom: 1px solid var(--border); cursor: pointer; font-size: 12px;";
    item.innerHTML = `
      <div style="font-weight: 600; color: var(--text);">${escapeHtml(f.name)}</div>
      <div style="font-size: 11px; color: var(--text-muted); font-family: monospace;">${escapeHtml(f.address)} &bull; ${f.size} B</div>
    `;
    item.addEventListener("click", () => {
      selectFunction(f);
    });
    list.appendChild(item);
  });
}

function selectFunction(func) {
  selectedFunction = func;
  document.getElementById("disasmTitle").textContent = `Function Disassembly: ${func.name} (${func.address})`;

  // Instructions viewer
  const disasmCode = document.getElementById("disasmCode");
  if (func.instructions && func.instructions.length > 0) {
    disasmCode.textContent = func.instructions.join("\n");
  } else {
    disasmCode.textContent = `; Function: ${func.name} at ${func.address} (size: ${func.size} bytes)\n; Deep instructions not extracted during quick triage.`;
  }

  // Decompiler viewer
  const decompilerCode = document.getElementById("decompilerCode");
  if (func.decompiled_c) {
    decompilerCode.textContent = func.decompiled_c;
    document.getElementById("decompilerEngineLabel").textContent = "radare2 Pseudo-C Decompiler";
  } else if (func.decompiled_csharp) {
    decompilerCode.textContent = func.decompiled_csharp;
    document.getElementById("decompilerEngineLabel").textContent = "ILSpy C# Decompiler";
  } else {
    decompilerCode.textContent = `// Decompiler representation for ${func.name}:\nvoid ${func.name}() {\n    // Function body size: ${func.size} bytes\n    // Recovered via ${func.source_tool}\n}`;
  }

  // CFG viewer
  const cfgContainer = document.getElementById("cfgContainer");
  cfgContainer.innerHTML = "";
  if (func.cfg_blocks && func.cfg_blocks.length > 0) {
    func.cfg_blocks.forEach((b) => {
      const bDiv = document.createElement("div");
      bDiv.className = "cfg-node";
      bDiv.innerHTML = `
        <div class="cfg-header">
          <strong>${escapeHtml(b.id)} (${escapeHtml(b.address)})</strong>
          <span>Size: ${b.size} B</span>
        </div>
        <div style="color: #b8c4e0; margin-bottom: 6px;">${escapeHtml((b.instructions || []).join("\n"))}</div>
        <div style="font-size: 11px; color: var(--text-muted); display: flex; gap: 16px;">
          ${b.jump_target ? `<span>Jump &rarr; <code>${escapeHtml(b.jump_target)}</code></span>` : ""}
          ${b.fail_target ? `<span>Fallthrough &rarr; <code>${escapeHtml(b.fail_target)}</code></span>` : ""}
        </div>
      `;
      cfgContainer.appendChild(bDiv);
    });
  } else {
    cfgContainer.innerHTML = `<p style="color: var(--text-muted); font-size: 13px;">No CFG basic blocks available for this function.</p>`;
  }
}

async function explainCurrentFunction() {
  if (!selectedFunction) {
    alert("Select a function first.");
    return;
  }
  try {
    const res = await fetch("/api/ai/explain_function", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(selectedFunction),
    });
    const data = await res.json();
    alert(`[AI Function Explanation]\n${data.technical_summary}\n\nHypothesis: ${data.analyst_hypothesis}`);
  } catch (e) {
    alert("AI explanation failed: " + e.message);
  }
}

async function explainCurrentDecompilation() {
  if (!selectedFunction) {
    alert("Select a function first.");
    return;
  }
  explainCurrentFunction();
}

function renderAIAnalyst(report) {
  const container = document.getElementById("hypothesesContainer");
  container.innerHTML = "";

  const hypotheses = report.ai_hypotheses || [];
  if (hypotheses.length === 0) {
    container.innerHTML = `<p style="color: var(--text-muted); font-size: 13px;">No high-risk security hypotheses generated. Sample exhibits standard executable patterns.</p>`;
  } else {
    hypotheses.forEach((h) => {
      const card = document.createElement("div");
      card.style.cssText = "background: var(--surface); border-left: 4px solid var(--warning); border-radius: 4px; padding: 14px; margin-bottom: 12px;";
      card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
          <strong style="color: var(--text); font-size: 14px;">${escapeHtml(h.title)}</strong>
          <span class="badge badge-warning">${Math.round(h.confidence * 100)}% Confidence</span>
        </div>
        <p style="font-size: 13px; color: #b8c4e0; margin-bottom: 8px;">${escapeHtml(h.description)}</p>
        <div style="font-size: 11px; color: var(--text-muted);">Grounding Evidence: ${h.supporting_evidence_ids.map(id => `<code>${escapeHtml(id)}</code>`).join(" ")}</div>
      `;
      container.appendChild(card);
    });
  }

  // Brief container
  const brief = document.getElementById("aiBriefContainer");
  const assessment = report.summary && report.summary.assessment ? report.summary.assessment : {};
  brief.textContent = JSON.stringify(assessment, null, 2);
}

async function runSandboxExecution() {
  const consent = document.getElementById("sandboxConsent");
  if (!consent.checked) {
    alert("You must confirm explicit authorization before executing dynamic analysis.");
    return;
  }

  if (!currentReport) {
    alert("No active binary analyzed.");
    return;
  }

  const out = document.getElementById("sandboxOutput");
  out.style.display = "block";
  out.textContent = "Executing sample in isolated disposable sandbox jail...";

  try {
    const res = await fetch("/api/dynamic/execute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sample_path: currentReport.sample.filename,
        report_id: currentReport.report_id,
        authorized: true,
        confirmation_token: "ANALYST_EXPLICIT_CONFIRMATION_" + Date.now(),
        timeout: 15,
      }),
    });
    const data = await res.json();
    out.textContent = JSON.stringify(data, null, 2);
    if (data.executed) {
      alert(`Controlled execution completed!\nExit code: ${data.exit_code}\nExecution time: ${data.execution_time_ms} ms`);
    }
  } catch (e) {
    out.textContent = "Sandbox execution error: " + e.message;
  }
}

async function triggerGhidraDecompilation() {
  if (!currentReport) return alert("Upload a sample first.");
  const btn = document.getElementById("ghidraDecompileBtn");
  if (btn) btn.textContent = "Running Ghidra Headless...";
  try {
    const res = await fetch(`/api/deep/ghidra/${currentReport.report_id}`, { method: "POST" });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Ghidra run failed");
    }
    currentReport = await res.json();
    renderReport(currentReport);
    alert("Ghidra headless decompilation complete! Functions and symbols updated.");
  } catch (e) {
    alert("Ghidra execution error: " + e.message);
  } finally {
    if (btn) btn.textContent = "Run Ghidra Headless";
  }
}

async function triggerAngrSymbolic() {
  if (!currentReport) return alert("Upload a sample first.");
  const btn = document.getElementById("angrSymbolicBtn");
  if (btn) btn.textContent = "Running angr CFGFast...";
  try {
    const res = await fetch(`/api/deep/angr/${currentReport.report_id}`, { method: "POST" });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "angr run failed");
    }
    currentReport = await res.json();
    renderReport(currentReport);
    alert("angr symbolic analysis complete! CFG findings updated.");
  } catch (e) {
    alert("angr execution error: " + e.message);
  } finally {
    if (btn) btn.textContent = "Run angr Symbolic CFG";
  }
}

async function loadTools() {
  const grid = document.getElementById("toolEcosystemGrid");
  try {
    const res = await fetch("/api/tools");
    const tools = await res.json();

    grid.innerHTML = "";
    Object.keys(tools).forEach((k) => {
      const t = tools[k];
      const card = document.createElement("div");
      card.className = "tool-card";

      const badge = t.installed
        ? '<span class="badge badge-success">Ready</span>'
        : '<span class="badge badge-danger">Missing</span>';

      card.innerHTML = `
        <div class="tool-header">
          <span class="tool-title">${escapeHtml(t.name)}</span>
          ${badge}
        </div>
        <div style="font-size: 11px; color: var(--accent); margin-bottom: 4px;">${escapeHtml(t.category)} &bull; ${escapeHtml(t.version || "N/A")}</div>
        <div class="tool-desc">${escapeHtml(t.description)}</div>
        <div class="tool-hint">${escapeHtml(t.path || t.install_hint)}</div>
      `;
      grid.appendChild(card);
    });
  } catch (e) {
    grid.innerHTML = `<p style="color: var(--danger);">Failed to audit tools: ${e.message}</p>`;
  }
}

function initTabs() {
  const tabBtns = document.querySelectorAll(".tab-btn");
  tabBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      tabBtns.forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));

      btn.classList.add("active");
      const target = document.getElementById(btn.dataset.tab);
      if (target) target.classList.add("active");
    });
  });
}

function initFilters() {
  const sel = document.getElementById("findingFilter");
  if (!sel) return;
  sel.addEventListener("change", (e) => {
    const val = e.target.value;
    document.querySelectorAll("#findingsTableBody tr").forEach((tr) => {
      if (val === "all" || tr.dataset.type === val) {
        tr.style.display = "";
      } else {
        tr.style.display = "none";
      }
    });
  });
}

function initVoice() {
  const voiceBtn = document.getElementById("voiceBtn");
  if (!("webkitSpeechRecognition" in window || "SpeechRecognition" in window)) {
    voiceBtn.style.opacity = "0.5";
    voiceBtn.title = "Web Speech API not supported in this browser";
    return;
  }

  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  const recognition = new SpeechRecognition();
  recognition.continuous = false;
  recognition.lang = "en-US";

  voiceBtn.addEventListener("click", () => {
    recognition.start();
    voiceBtn.style.borderColor = "var(--accent)";
  });

  recognition.onresult = (e) => {
    voiceBtn.style.borderColor = "var(--border)";
    const cmd = e.results[0][0].transcript.toLowerCase();
    handleVoiceCommand(cmd);
  };

  recognition.onerror = () => {
    voiceBtn.style.borderColor = "var(--border)";
  };
}

function handleVoiceCommand(cmd) {
  if (cmd.includes("upload")) {
    document.getElementById("fileInput").click();
  } else if (cmd.includes("finding") || cmd.includes("evidence")) {
    switchTab("tabFindings");
  } else if (cmd.includes("section")) {
    switchTab("tabSections");
  } else if (cmd.includes("import")) {
    switchTab("tabImports");
  } else if (cmd.includes("function") || cmd.includes("disassembly")) {
    switchTab("tabFunctions");
  } else if (cmd.includes("decompile")) {
    switchTab("tabDecompiler");
  } else if (cmd.includes("tool")) {
    switchTab("tabTools");
  } else if (cmd.includes("download json")) {
    downloadReportJson();
  } else if (cmd.includes("download markdown")) {
    downloadReportMarkdown();
  }
}

function switchTab(tabId) {
  document.querySelectorAll(".tab-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.tab === tabId);
  });
  document.querySelectorAll(".tab-content").forEach((c) => {
    c.classList.toggle("active", c.id === tabId);
  });
}

function downloadReportJson() {
  if (!currentReport) return alert("No active report.");
  window.open(`/api/report/${currentReport.report_id}/json`, "_blank");
}

function downloadReportMarkdown() {
  if (!currentReport) return alert("No active report.");
  window.open(`/api/report/${currentReport.report_id}/markdown`, "_blank");
}

function downloadReportHtml() {
  if (!currentReport) return alert("No active report.");
  window.open(`/api/report/${currentReport.report_id}/html`, "_blank");
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
