# 🔬 Jarvis RE — Analysis Report

**Sample:** `{{ sample.filename }}`
**Generated:** {{ generated_at }}

---

## 📋 Sample Information

| Property | Value |
|:---------|:------|
| **Filename** | `{{ sample.filename }}` |
| **SHA-256** | `{{ sample.sha256 }}` |
{% if sample.md5 %}| **MD5** | `{{ sample.md5 }}` |
{% endif %}{% if sample.sha1 %}| **SHA-1** | `{{ sample.sha1 }}` |
{% endif %}| **File Size** | {{ sample.file_size | filesizeformat }} |
| **File Type** | {{ sample.file_type or "Unknown" }} |
| **Architecture** | {{ sample.architecture or "Unknown" }} |

{% if sample.metadata %}
### Additional Metadata

{% for key, value in sample.metadata.items() %}
- **{{ key }}:** {{ value }}
{% endfor %}
{% endif %}

---

## 📊 Executive Summary

| Metric | Value |
|:-------|:------|
| **Total Findings** | {{ summary.total_findings }} |
| **Tools Used** | {{ summary.tools_used | join(", ") }} |
| **Analysis Duration** | {{ summary.analysis_duration or "N/A" }} |
| **Overall Status** | {{ summary.overall_status }} |

### Findings by Type

| Type | Count |
|:-----|------:|
{% for ftype, count in summary.by_type.items() %}| {{ ftype }} | {{ count }} |
{% endfor %}

### Findings by Tool

| Tool | Count |
|:-----|------:|
{% for tool, count in summary.by_tool.items() %}| {{ tool }} | {{ count }} |
{% endfor %}

### Confidence Distribution

| Level | Count |
|:------|------:|
{% for level, count in summary.by_confidence.items() %}| {{ level }} | {{ count }} |
{% endfor %}

{% if summary.key_observations %}
### Key Observations

{% for obs in summary.key_observations %}
- {{ obs }}
{% endfor %}
{% endif %}

---

## 🔍 Findings

{% if findings %}
### All Findings ({{ findings | length }})

| # | Type | Name | Tool | Confidence | Status | Address |
|--:|:-----|:-----|:-----|:-----------|:-------|:--------|
{% for f in findings %}| {{ loop.index }} | {{ f.finding_type }} | {{ f.name or "—" }} | {{ f.source_tool }} | {{ "%.0f" | format(f.confidence * 100) }}% | {{ f.status }} | `{{ f.address or "—" }}` |
{% endfor %}

{% for f in findings %}
---

#### Finding #{{ loop.index }}: {{ f.finding_type | upper }} — {{ f.name or "Unnamed" }}

- **Source Tool:** {{ f.source_tool }}
- **Confidence:** {{ "%.0f" | format(f.confidence * 100) }}%
- **Status:** {{ f.status }}
{% if f.address %}- **Address:** `{{ f.address }}`{% endif %}
{% if f.description %}
- **Description:** {{ f.description }}
{% endif %}

{% if f.evidence %}
**Evidence:**

{% for e in f.evidence %}
> **{{ e.source }}** {% if e.timestamp %}({{ e.timestamp }}){% endif %}
> {{ e.content }}
{% if e.artifact_path %}> 📎 Artifact: `{{ e.artifact_path }}`{% endif %}

{% endfor %}
{% endif %}

{% if f.raw_data %}
<details>
<summary>Raw Data</summary>

```json
{{ f.raw_data | tojson(indent=2) }}
```

</details>
{% endif %}

{% endfor %}

{% else %}
*No findings were produced during this analysis.*
{% endif %}

---

## ⚙️ Analysis Jobs

{% if jobs %}
| Job ID | Type | Status | Progress | Started | Completed | Findings |
|:-------|:-----|:-------|:---------|:--------|:----------|:---------|
{% for j in jobs %}| `{{ j.id[:8] }}…` | {{ j.job_type }} | {{ j.status }} | {{ j.progress }}% | {{ j.started_at or "—" }} | {{ j.completed_at or "—" }} | {{ j.findings_count }} |
{% endfor %}

{% for j in jobs %}
{% if j.error_message %}
> ⚠️ **Job `{{ j.id[:8] }}…` error:** {{ j.error_message }}
{% endif %}
{% endfor %}

{% else %}
*No analysis jobs recorded.*
{% endif %}

---

## 📌 Notes

- All findings start with status **unverified** and require manual or AI-assisted review.
- Confidence scores are tool-specific heuristics and should not be treated as absolute certainty.
- This report was generated automatically by **Jarvis RE Module v0.1.0**.

---

*Report generated at {{ generated_at }} by Jarvis OMEGA — Reverse Engineering Module*
