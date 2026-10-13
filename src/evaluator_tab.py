"""
PAnGEA — Evaluator tab for pangea_app.py.

For each capture in src/pcaps that has a description and steps:
  1. preprocess (cached in <name>_clusters.json),
  2. ground the steps with the bi-encoder + cross-encoder (cached in
     <name>_grounding.json, all top-k candidates kept),
  3. label step x cluster pairs in the browser (saved to <name>_gt.json),
  4. see Precision@1, MRR, Jaccard, no-match accuracy, coverage and
     ambiguity per capture and pooled over the dataset.

Thresholds are applied to the saved grounding run, so moving the sliders
re-scores instantly without re-running the models.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from evaluator import EvaluationReport, evaluate_against, ground_truth_from_dict
from Grounder.grounder import (
    DEFAULT_AMBIGUITY_THRESHOLD,
    DEFAULT_PARTIAL_THRESHOLD,
    DEFAULT_SUPPORTS_THRESHOLD,
    DEFAULT_TOP_K_BIENCODER,
    GrounderModels,
)
from Grounder.schemas import GrounderOutput, Step
from pcap_dataset import (
    GT_LABELS,
    Entry,
    cluster_label,
    grounder_output_from_dict,
    list_entries,
    load_clusters,
    load_grounding,
    load_gt,
    preprocess,
    rethreshold,
    run_grounding,
    save_gt,
)
from Preprocessor.visualize import render_html

DEFAULT_NEUTRAL_THRESHOLD = 0.40
NO_LABEL = ""
LABEL_OPTIONS = [NO_LABEL, *GT_LABELS]


@st.cache_resource(show_spinner="Loading bi-encoder and cross-encoder (first time only)…")
def _models() -> GrounderModels:
    return GrounderModels.default()


# ---------------------------------------------------------------------------
# Per-capture state
# ---------------------------------------------------------------------------

@dataclass
class EntryState:
    entry: Entry
    steps: list[Step]
    clusters: Optional[dict]              # cached preprocessor payload
    grounding_raw: Optional[GrounderOutput]
    grounding_settings: Optional[dict]
    grounding: Optional[GrounderOutput]   # after thresholds
    gt: dict
    report: Optional[EvaluationReport]

    @property
    def clusters_by_key(self) -> dict[str, dict]:
        if not self.clusters:
            return {}
        return {c["fingerprint_key"]: c for c in self.clusters["output"]["clusters"]}

    @property
    def grounding_stale(self) -> bool:
        return bool(self.grounding_raw and self.clusters
                     and self.grounding_settings != self.clusters["settings"])

    @property
    def gt_stale(self) -> bool:
        saved = self.gt.get("preprocess_settings")
        return bool(saved and self.clusters and saved != self.clusters["settings"])

    @property
    def reviewed(self) -> set[int]:
        return set(ground_truth_from_dict(self.gt))


def _load_state(entry: Entry, thr: dict) -> EntryState:
    clusters = load_clusters(entry)
    g = load_grounding(entry)
    raw = grounder_output_from_dict(g["grounding"]) if g else None
    thresholded = rethreshold(raw, **thr) if raw else None
    gt = load_gt(entry)
    gt_map = ground_truth_from_dict(gt)
    report = evaluate_against(thresholded, gt_map) if thresholded and gt_map else None
    return EntryState(
        entry=entry, steps=entry.steps(), clusters=clusters,
        grounding_raw=raw, grounding_settings=g["preprocess_settings"] if g else None,
        grounding=thresholded, gt=gt, report=report,
    )


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def _pooled(reports: list[EvaluationReport]) -> Optional[dict]:
    """Micro-average over every reviewed step of every capture."""
    results = [r for rep in reports for r in rep.step_results]
    n = sum(rep.n_steps for rep in reports)
    if not n:
        return None
    p1 = [r.precision_at_1 for r in results if r.precision_at_1 is not None]
    nm = [r.is_correct_no_match for r in results if r.is_correct_no_match is not None]
    mean = lambda xs: sum(xs) / len(xs) if xs else None
    return {
        "steps": n,
        "precision_at_1": mean(p1),
        "mrr": mean([r.reciprocal_rank for r in results]),
        "mean_jaccard": mean([r.jaccard for r in results]),
        "no_match_accuracy": mean([float(b) for b in nm]),
        "coverage": sum(rep.n_grounded_steps for rep in reports) / n,
        "ambiguity_rate": sum(rep.n_ambiguous_steps for rep in reports) / n,
    }


def _fmt(x: Optional[float]) -> str:
    return "—" if x is None else f"{x:.2f}"


def _metric_row(m: Optional[dict], reviewed: int, total: int) -> None:
    cols = st.columns(7)
    cols[0].metric("Reviewed steps", f"{reviewed} / {total}")
    if not m:
        for c, label in zip(cols[1:], ["Precision@1", "MRR", "Jaccard", "No-match acc.", "Coverage", "Ambiguity"]):
            c.metric(label, "—")
        return
    cols[1].metric("Precision@1", _fmt(m["precision_at_1"]),
                   help="Top-ranked cluster is SUPPORTS (1) or PARTIAL (0.5). Ungrounded steps excluded.")
    cols[2].metric("MRR", _fmt(m["mrr"]), help="Mean reciprocal rank of the first SUPPORTS/PARTIAL cluster.")
    cols[3].metric("Jaccard", _fmt(m["mean_jaccard"]), help="Overlap of predicted and ground-truth cluster sets.")
    cols[4].metric("No-match acc.", _fmt(m["no_match_accuracy"]),
                   help="Share of steps with no positive label that the grounder left ungrounded.")
    cols[5].metric("Coverage", _fmt(m["coverage"]), help="Share of steps with any cluster above the neutral threshold.")
    cols[6].metric("Ambiguity", _fmt(m["ambiguity_rate"]), help="Share of steps whose top-2 score gap is below the ambiguity threshold.")


def _report_dict(rep: EvaluationReport) -> dict:
    return {
        "steps": rep.n_steps, "precision_at_1": rep.precision_at_1 if any(
            r.precision_at_1 is not None for r in rep.step_results) else None,
        "mrr": rep.mrr, "mean_jaccard": rep.mean_jaccard,
        "no_match_accuracy": rep.no_match_accuracy,
        "coverage": rep.coverage, "ambiguity_rate": rep.ambiguity_rate,
    }


# ---------------------------------------------------------------------------
# UI pieces
# ---------------------------------------------------------------------------

def _threshold_controls() -> dict:
    with st.expander("Grounder thresholds", expanded=False):
        c1, c2, c3, c4 = st.columns(4)
        sup = c1.slider("SUPPORTS ≥", 0.0, 1.0, DEFAULT_SUPPORTS_THRESHOLD, 0.01, key="thr_sup")
        par = c2.slider("PARTIAL ≥", 0.0, 1.0, DEFAULT_PARTIAL_THRESHOLD, 0.01, key="thr_par")
        neu = c3.slider("Returned (neutral) ≥", 0.0, 1.0, DEFAULT_NEUTRAL_THRESHOLD, 0.01, key="thr_neu")
        amb = c4.slider("Ambiguous if top-2 gap <", 0.0, 0.5, DEFAULT_AMBIGUITY_THRESHOLD, 0.01, key="thr_amb")
        st.caption("Applied to the saved grounding runs. Changing them re-scores every capture "
                   "instantly; the models are not re-run.")
    if not (neu <= par <= sup):
        st.error("Thresholds must satisfy returned ≤ PARTIAL ≤ SUPPORTS. Using the defaults until fixed.")
        sup, par, neu = DEFAULT_SUPPORTS_THRESHOLD, DEFAULT_PARTIAL_THRESHOLD, DEFAULT_NEUTRAL_THRESHOLD
    return {"supports_threshold": sup, "partial_threshold": par,
            "neutral_threshold": neu, "ambiguity_threshold": amb}


def _overview(states: list[EntryState]) -> None:
    rows = []
    for s in states:
        stats = s.clusters["output"]["compression_stats"] if s.clusters else None
        rep = _report_dict(s.report) if s.report else {}
        rows.append({
            "Capture": s.entry.name,
            "Steps": len(s.steps),
            "Packets": stats["raw_packet_count_in"] if stats else None,
            "Clusters": stats["cluster_count"] if stats else None,
            "Grounded": "stale" if s.grounding_stale else ("yes" if s.grounding_raw else "—"),
            "Reviewed": f"{len(s.reviewed)}/{len(s.steps)}" if s.steps else "—",
            "P@1": rep.get("precision_at_1"),
            "MRR": rep.get("mrr"),
            "Jaccard": rep.get("mean_jaccard"),
            "No-match": rep.get("no_match_accuracy"),
        })
    st.dataframe(
        pd.DataFrame(rows), hide_index=True, width="stretch",
        column_config={k: st.column_config.NumberColumn(format="%.2f") for k in ("P@1", "MRR", "Jaccard", "No-match")},
    )


def _actions(state: EntryState) -> None:
    e = state.entry
    c1, c2, c3 = st.columns([1, 1, 3])
    stats = state.clusters["output"]["compression_stats"] if state.clusters else None

    if c1.button("Re-run preprocessing" if state.clusters else "Run preprocessing", key=f"pre_{e.name}"):
        with st.spinner(f"Dissecting and clustering {e.name} (large captures take minutes)…"):
            try:
                preprocess(e)
            except Exception as exc:
                st.error(f"Preprocessing failed: {type(exc).__name__}: {exc}")
                return
        st.rerun()

    ground_label = "Re-run grounding" if state.grounding_raw else "Run grounding"
    if c2.button(ground_label, key=f"gr_{e.name}", type="primary" if not state.grounding_raw else "secondary",
                 disabled=not (state.clusters and state.steps)):
        with st.spinner(f"Grounding {len(state.steps)} steps against {stats['cluster_count']} clusters…"):
            try:
                run_grounding(e, _models(), top_k=DEFAULT_TOP_K_BIENCODER)
            except Exception as exc:
                st.error(f"Grounding failed: {type(exc).__name__}: {exc}")
                return
        st.rerun()

    if state.grounding_raw:
        g = state.grounding_raw
        c3.caption(f"Grounded with `{g.model_bi_encoder}` → `{g.model_cross_encoder}`, "
                   f"top-k {g.parameters.get('top_k')}, {g.clusters_scored} clusters scored.")
    if state.grounding_stale:
        st.warning("The clusters were rebuilt with different settings after this grounding run. Re-run grounding.")
    if state.gt_stale:
        st.warning("The ground truth was labelled on clusters built with different preprocessor settings; "
                   "fingerprint keys may no longer match.")


def _cluster_browser(state: EntryState) -> None:
    payload = state.clusters
    with st.expander(f"Browse all {len(payload['output']['clusters'])} clusters"):
        rows = [{
            "Cluster": cluster_label(c["fingerprint_key"]),
            "Tier": (c.get("metadata") or {}).get("tier"),
            "Packets": (c.get("aggregate") or {}).get("count"),
            "Serialization": (c.get("metadata") or {}).get("cluster_text"),
        } for c in payload["output"]["clusters"]]
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
        if st.toggle("Show bubble viewer", key=f"viewer_{state.entry.name}"):
            components.html(
                render_html(payload["output"], source=payload.get("pcap"),
                            delta_t=payload["settings"]["delta_t"]),
                height=1100, scrolling=True,
            )


def _cluster_names(clusters_by_key: dict[str, dict]) -> dict[str, str]:
    """Unique display name per fingerprint key (labels can repeat across time windows)."""
    return {key: f"c{i:02d} · {cluster_label(key)}" for i, key in enumerate(clusters_by_key, start=1)}


def _step_block(state: EntryState, sg, names: dict[str, str], gt_labels: dict, reviewed: set[int]):
    """Render one step; returns (labels {fkey: label}, reviewed flag)."""
    step = sg.step
    clusters = state.clusters_by_key
    raw = next(r for r in state.grounding_raw.step_groundings if r.step.step_id == step.step_id)
    kept = {gr.cluster_fingerprint_key: gr.evidence_label.value for gr in sg.matched_clusters}

    status = []
    if sg.is_ungrounded:
        status.append(":gray-badge[ungrounded]")
    else:
        top = sg.matched_clusters[0].evidence_label.value
        status.append({"SUPPORTS": ":green-badge[top: SUPPORTS]", "PARTIAL": ":orange-badge[top: PARTIAL]"}
                      .get(top, ":gray-badge[top: NEUTRAL]"))
    if sg.is_ambiguous:
        status.append(":violet-badge[ambiguous]")
    if step.mitre_tag:
        status.append(f":blue-badge[{step.mitre_tag}]")
    if step.step_id in reviewed:
        status.append(":green-badge[reviewed]")

    st.markdown(f"**Step {step.step_id}.** {step.text}  \n" + " ".join(status))
    st.caption(f"From the description: “{step.source_text}”")

    my = {k: v for (sid, k), v in gt_labels.items() if sid == step.step_id}
    cand_keys = [gr.cluster_fingerprint_key for gr in raw.matched_clusters]
    cand_rows = []
    for gr in raw.matched_clusters:
        c = clusters.get(gr.cluster_fingerprint_key, {})
        cand_rows.append({
            "key": gr.cluster_fingerprint_key,
            "Rank": gr.rank,
            "Cluster": names.get(gr.cluster_fingerprint_key, cluster_label(gr.cluster_fingerprint_key)),
            "Tier": (c.get("metadata") or {}).get("tier"),
            "Packets": (c.get("aggregate") or {}).get("count"),
            "Score": gr.score,
            "Bi-enc": gr.bi_encoder_score,
            "Predicted": kept.get(gr.cluster_fingerprint_key, "below threshold"),
            "Your label": my.get(gr.cluster_fingerprint_key, NO_LABEL),
            "Serialization": gr.cluster_text,
        })
    edited = st.data_editor(
        pd.DataFrame(cand_rows),
        key=f"cand_{state.entry.name}_{step.step_id}",
        hide_index=True, width="stretch",
        disabled=["Rank", "Cluster", "Tier", "Packets", "Score", "Bi-enc", "Predicted", "Serialization"],
        column_config={
            "key": None,
            "Rank": st.column_config.NumberColumn(width="small"),
            "Score": st.column_config.ProgressColumn(min_value=0.0, max_value=1.0, format="%.3f",
                                                     help="Cross-encoder score (sigmoid)"),
            "Bi-enc": st.column_config.NumberColumn(format="%.3f", help="Stage-1 cosine similarity"),
            "Your label": st.column_config.SelectboxColumn(options=LABEL_OPTIONS, required=False),
            "Serialization": st.column_config.TextColumn(width="large"),
        },
    )
    labels = {r["key"]: r["Your label"] for r in edited.to_dict("records") if r["Your label"]}

    # Clusters outside the grounder's top-k can be labelled too, so the ground
    # truth is not limited to what the model retrieved.
    other_opts = {names[k]: k for k in clusters if k not in cand_keys}
    other_rows = [{"Cluster": names[k], "Your label": v} for k, v in my.items()
                  if k not in cand_keys and k in names]
    if other_opts:
        other = st.data_editor(
            pd.DataFrame(other_rows, columns=["Cluster", "Your label"]),
            key=f"other_{state.entry.name}_{step.step_id}",
            num_rows="dynamic", hide_index=True, width="stretch",
            column_config={
                "Cluster": st.column_config.SelectboxColumn(
                    "Other cluster (not retrieved)", options=sorted(other_opts), required=True),
                "Your label": st.column_config.SelectboxColumn(options=GT_LABELS, required=True),
            },
        )
        for r in other.to_dict("records"):
            if r.get("Cluster") in other_opts and r.get("Your label"):
                labels[other_opts[r["Cluster"]]] = r["Your label"]

    done = st.checkbox(
        "Reviewed (no SUPPORTS/PARTIAL label means the step should have no match)",
        value=step.step_id in reviewed,
        key=f"rev_{state.entry.name}_{step.step_id}",
    )
    return labels, done


def _annotation_form(state: EntryState) -> None:
    gt_labels = {(a["step_id"], a["fingerprint_key"]): a["label"] for a in state.gt.get("annotations", [])}
    reviewed = state.reviewed
    names = _cluster_names(state.clusters_by_key)

    with st.form(f"gt_form_{state.entry.name}", border=False):
        top = st.columns([2, 1, 3])
        previous = next((a["annotator"] for a in state.gt.get("annotations", []) if a.get("annotator")), "")
        annotator = top[0].text_input("Annotator", value=previous, key=f"annot_{state.entry.name}",
                                      help="Stored with each label, for inter-annotator agreement.")
        submitted_top = top[1].form_submit_button("Save ground truth", type="primary")
        top[2].caption("Label the clusters that support each step. Rows show the grounder's top-k "
                       "candidates; use the second table to label any other cluster.")

        all_labels: dict[tuple[int, str], str] = {}
        done_steps: set[int] = set()
        for sg in state.grounding.step_groundings:
            with st.container(border=True):
                labels, done = _step_block(state, sg, names, gt_labels, reviewed)
            for k, v in labels.items():
                all_labels[(sg.step.step_id, k)] = v
            if done or labels:
                done_steps.add(sg.step.step_id)

        submitted_bottom = st.form_submit_button("Save ground truth", type="primary")

    if submitted_top or submitted_bottom:
        save_gt(state.entry, state.steps, all_labels, done_steps, state.clusters_by_key,
                state.clusters["settings"], annotator=annotator.strip() or None)
        st.toast(f"Saved {len(all_labels)} labels for {len(done_steps)} steps to {state.entry.gt_path.split('/')[-1]}")
        st.rerun()


def _per_step_results(state: EntryState) -> None:
    if not state.report:
        return
    names = _cluster_names(state.clusters_by_key)
    short = lambda keys: ", ".join(sorted(names.get(k, "?").split(" · ")[0] for k in keys))
    rows = [{
        "Step": r.step_id,
        "P@1": r.precision_at_1,
        "RR": r.reciprocal_rank,
        "Jaccard": r.jaccard,
        "Predicted": short(r.predicted_keys) or "∅",
        "Ground truth": short(r.gt_keys) or "∅ (no match)",
    } for r in state.report.step_results]
    with st.expander("Per-step results"):
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch",
                     column_config={k: st.column_config.NumberColumn(format="%.2f") for k in ("P@1", "RR", "Jaccard")})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def render_evaluator_tab() -> None:
    entries = [e for e in list_entries() if e.has(e.text_path) and e.has(e.steps_path)]
    if not entries:
        st.info("No captures with a description (<name>.txt) and steps (<name>_steps.json) in src/pcaps.")
        return

    thr = _threshold_controls()
    states = [_load_state(e, thr) for e in entries]

    st.subheader("Dataset")
    pooled = _pooled([s.report for s in states if s.report])
    _metric_row(pooled, sum(len(s.reviewed) for s in states), sum(len(s.steps) for s in states))
    _overview(states)

    st.subheader("Capture")
    name = st.selectbox("Capture", [s.entry.name for s in states], key="eval_entry", label_visibility="collapsed")
    state = next(s for s in states if s.entry.name == name)

    with st.expander("Description"):
        st.text(state.entry.description() or "")
    _actions(state)

    if not state.clusters:
        st.info("Run preprocessing to build the clusters for this capture.")
        return
    _cluster_browser(state)
    if not state.grounding:
        st.info("Run grounding to match the steps to clusters. The first run in a session loads "
                "the two models, which takes about a minute.")
        return

    _metric_row(_report_dict(state.report) if state.report else None, len(state.reviewed), len(state.steps))
    _per_step_results(state)
    _annotation_form(state)
