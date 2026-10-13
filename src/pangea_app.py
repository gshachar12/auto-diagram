"""
PAnGEA — upload a PCAP and a description, run the preprocessor, explore
the resulting clusters in the interactive viewer, and ground the
description's steps against those clusters.

The Evaluator tab works on the dataset in src/pcaps (see evaluator_tab.py).

Run from src/:
    streamlit run pangea_app.py
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from Preprocessor.layer2_fingerprint import DEFAULT_DELTA_T
from Preprocessor.preprocessor import run_preprocessing
from Preprocessor.visualize import render_html
from Grounder.schemas import Step
from Grounder.step_extractor import StepExtractionError, extract_steps, steps_from_records
from Grounder import grounder as G
from evaluator_tab import render_evaluator_tab

st.set_page_config(page_title="PAnGEA Clusters", layout="wide")

# Step-extractor LLM outputs are always written here (CLAUDE.md §12).
EXTRACTED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "outputs", "extracted")
DEFAULT_EXTRACTOR_MODEL = "gpt-4o-2024-08-06"   # dated snapshot, not an alias

EVIDENCE_ICON = {"SUPPORTS": "🟢", "PARTIAL": "🟡", "NEUTRAL": "⚪"}


@st.cache_data(show_spinner=False, max_entries=8)
def _run(pcap_bytes: bytes, description: str, token_budget: int,
         filtering_limit: int, delta_t: float, max_packets: int | None) -> dict:
    # Cached on the exact inputs, so re-rendering the page never re-runs tshark.
    output = run_preprocessing(
        pcap_bytes=pcap_bytes,
        attack_description=description,
        token_budget=token_budget,
        filtering_limit=filtering_limit,
        delta_t=delta_t,
        max_packets=max_packets,
    )
    return asdict(output)


@st.cache_resource(show_spinner=False, max_entries=2)
def _load_models(bi_encoder: str, cross_encoder: str) -> G.GrounderModels:
    return G.GrounderModels(bi_encoder_model=bi_encoder, cross_encoder_model=cross_encoder).load()


@st.cache_data(show_spinner=False, max_entries=16)
def _ground(steps_json: str, clusters_json: str, bi_encoder: str, cross_encoder: str,
            params_json: str) -> dict:
    # Inputs are passed as JSON strings so the cache key is the exact content.
    output = G.ground(
        steps=steps_from_records(json.loads(steps_json)),
        clusters=json.loads(clusters_json),
        models=_load_models(bi_encoder, cross_encoder),
        **json.loads(params_json),
    )
    return G.grounder_output_to_dict(output)


def _openai_text_client(api_key: str, model: str):
    """prompt -> response text, temperature 0, as extract_steps() expects."""
    from openai import OpenAI
    client = OpenAI(api_key=api_key)

    def call(prompt: str) -> str:
        resp = client.chat.completions.create(
            model=model, temperature=0,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.choices[0].message.content or ""
    return call


def _steps_to_records(steps: list[Step]) -> list[dict]:
    return [asdict(s) for s in steps]


def render_upload_tab() -> None:
    """Upload a capture + description, explore its clusters, ground its steps."""
    # ---------------------------------------------------------------------------
    # Inputs
    # ---------------------------------------------------------------------------

    st.title("PAnGEA cluster explorer")
    st.caption("Upload a capture and its attack description. The preprocessor clusters the packets; "
               "the description is used only to extract the attack context for relevance scoring "
               "and, in the Grounding tab, the steps to match against clusters.")

    col_pcap, col_desc = st.columns(2, gap="large")
    with col_pcap:
        pcap_file = st.file_uploader("PCAP file", type=["pcap", "pcapng", "cap"])
    with col_desc:
        desc_file = st.file_uploader("Description (.txt)", type=["txt", "md"])
        desc_text = st.text_area(
            "…or paste the description",
            value=desc_file.getvalue().decode("utf-8", errors="replace") if desc_file else "",
            height=140,
            key=f"desc_{desc_file.file_id if desc_file else 'none'}",
        )

    with st.expander("Pipeline settings"):
        s1, s2, s3, s4 = st.columns(4)
        token_budget    = s1.number_input("Token budget", min_value=100, value=10000, step=1000)
        filtering_limit = s2.number_input("Sample packets per cluster", min_value=1, value=3, step=1)
        delta_t         = s3.number_input("Time window Δt (s)", min_value=1.0, value=float(DEFAULT_DELTA_T), step=60.0)
        max_packets     = s4.number_input("Max packets (0 = all)", min_value=0, value=0, step=1000)

    ready = pcap_file is not None and desc_text.strip() != ""
    if st.button("Run preprocessing", type="primary", disabled=not ready):
        st.session_state["run_args"] = dict(
            pcap_bytes=pcap_file.getvalue(),
            description=desc_text,
            token_budget=int(token_budget),
            filtering_limit=int(filtering_limit),
            delta_t=float(delta_t),
            max_packets=int(max_packets) or None,
            pcap_name=pcap_file.name,
            desc_name=desc_file.name if desc_file else None,
        )
    if not ready:
        st.info("Add a PCAP file and a description to run the preprocessor.")

    args = st.session_state.get("run_args")
    if not args:
        return

    run_kwargs = {k: v for k, v in args.items() if k not in ("pcap_name", "desc_name")}
    try:
        with st.spinner(f"Dissecting and clustering {args['pcap_name']}…"):
            output = _run(**run_kwargs)
    except Exception as exc:  # surface tshark / parse errors instead of a blank page
        st.error(f"Preprocessing failed: {type(exc).__name__}: {exc}")
        return

    stats = output["compression_stats"]
    if not output["clusters"]:
        st.warning(f"No clusters were produced. {stats['raw_packet_count_in']} packets read, "
                   f"{stats['dropped_parse_failures']} could not be parsed.")
        return

    base = args["pcap_name"].rsplit(".", 1)[0]
    tab_clusters, tab_ground = st.tabs(["Clusters", "Grounding"])

    # ---------------------------------------------------------------------------
    # Clusters tab — interactive viewer
    # ---------------------------------------------------------------------------

    with tab_clusters:
        page = render_html(
            output,
            source=args["pcap_name"],
            description_file=args["desc_name"],
            delta_t=args["delta_t"],
        )
        d1, d2, _ = st.columns([1, 1, 4])
        d1.download_button("Download viewer (.html)", page, file_name=f"{base}_clusters.html", mime="text/html")
        d2.download_button("Download output (.json)", json.dumps(output, indent=2, default=str),
                           file_name=f"{base}_output.json", mime="application/json")
        components.html(page, height=1500, scrolling=True)

    # ---------------------------------------------------------------------------
    # Grounding tab — steps → clusters
    # ---------------------------------------------------------------------------

    with tab_ground:
        st.subheader("1 · Steps")
        st.caption("Traffic-observable steps from the description. LLM extractions are saved to disk "
                   "before use so a grounding run can always be reproduced from a static file.")

        # Steps are tied to the description they came from; a new description
        # starts with no steps rather than silently reusing old ones.
        desc_sig = hashlib.sha256(args["description"].encode("utf-8")).hexdigest()[:12]
        if st.session_state.get("steps_desc_sig") != desc_sig:
            st.session_state.pop("steps", None)
            st.session_state.pop("steps_origin", None)
            st.session_state["steps_desc_sig"] = desc_sig

        source = st.radio(
            "Step source",
            ["Upload extracted steps (.json)", "Write steps manually", "Extract with LLM (OpenAI)"],
            horizontal=True, label_visibility="collapsed",
        )

        if source == "Upload extracted steps (.json)":
            steps_file = st.file_uploader("extracted_*.json", type=["json"], key="steps_upload")
            if steps_file is not None:
                try:
                    steps = steps_from_records(json.loads(steps_file.getvalue().decode("utf-8")))
                    st.session_state["steps"] = _steps_to_records(steps)
                    st.session_state["steps_origin"] = f"uploaded {steps_file.name}"
                except (ValueError, KeyError, TypeError) as exc:
                    st.error(f"Could not read steps file: {type(exc).__name__}: {exc}")

        elif source == "Write steps manually":
            manual = st.text_area("One step per line", height=160, key=f"manual_{desc_sig}",
                                  placeholder="Many hosts send TCP SYN packets to port 80 of a single server\n"
                                              "The server answers with few SYN-ACK packets")
            if st.button("Use these steps"):
                lines = [ln.strip() for ln in manual.splitlines() if ln.strip()]
                st.session_state["steps"] = [
                    asdict(Step(step_id=i, text=ln, source_text=ln)) for i, ln in enumerate(lines, start=1)
                ]
                st.session_state["steps_origin"] = "written manually"

        else:
            c1, c2 = st.columns([2, 1])
            api_key = c1.text_input("OpenAI API key", type="password",
                                    value=os.environ.get("OPENAI_API_KEY", ""))
            model = c2.text_input("Model (pinned snapshot)", value=DEFAULT_EXTRACTOR_MODEL)
            if st.button("Extract steps", disabled=not api_key or not model):
                save_path = os.path.normpath(os.path.join(
                    EXTRACTED_DIR, f"extracted_{base}_{time.strftime('%Y%m%d-%H%M%S')}.json"))
                try:
                    with st.spinner(f"Extracting steps with {model}…"):
                        steps = extract_steps(args["description"], _openai_text_client(api_key, model),
                                              save_path=save_path)
                except StepExtractionError as exc:
                    st.error(str(exc))
                else:
                    if not steps:
                        st.warning("The model returned no steps.")
                    st.session_state["steps"] = _steps_to_records(steps)
                    st.session_state["steps_origin"] = f"extracted with {model}, saved to {save_path}"

        steps_records = st.session_state.get("steps")
        if steps_records:
            st.caption(f"{len(steps_records)} steps — {st.session_state.get('steps_origin', '')}")
            st.dataframe(pd.DataFrame(steps_records)[["step_id", "text", "source_text", "mitre_tag"]],
                         hide_index=True, width="stretch")
        else:
            st.info("No steps yet. Upload, write, or extract them above.")

        st.subheader("2 · Ground")
        with st.expander("Grounder settings"):
            g1, g2 = st.columns(2)
            bi_model = g1.text_input("Bi-encoder", value=G.DEFAULT_BI_ENCODER_MODEL)
            ce_model = g2.text_input("Cross-encoder", value=G.DEFAULT_CROSS_ENCODER_MODEL)
            t1, t2, t3, t4, t5 = st.columns(5)
            top_k     = t1.number_input("Top-k candidates", min_value=1, value=G.DEFAULT_TOP_K_BIENCODER)
            supports  = t2.number_input("SUPPORTS ≥", 0.0, 1.0, G.DEFAULT_SUPPORTS_THRESHOLD, 0.05)
            partial   = t3.number_input("PARTIAL ≥", 0.0, 1.0, G.DEFAULT_PARTIAL_THRESHOLD, 0.05)
            neutral   = t4.number_input("NEUTRAL ≥", 0.0, 1.0, G.DEFAULT_NEUTRAL_THRESHOLD, 0.05)
            ambiguity = t5.number_input("Ambiguity gap <", 0.0, 1.0, G.DEFAULT_AMBIGUITY_THRESHOLD, 0.01)
        params = dict(top_k=int(top_k), supports_threshold=supports, partial_threshold=partial,
                      neutral_threshold=neutral, ambiguity_threshold=ambiguity)
        thresholds_ok = neutral <= partial <= supports
        if not thresholds_ok:
            st.error("Thresholds must satisfy NEUTRAL ≤ PARTIAL ≤ SUPPORTS.")

        # Only what the grounder reads, so the cache key ignores unrelated fields.
        clusters_min = [
            {"fingerprint_key": c["fingerprint_key"], "cluster_text": (c.get("metadata") or {}).get("cluster_text")}
            for c in output["clusters"]
        ]
        ground_sig = hashlib.sha256(json.dumps(
            [steps_records, clusters_min, bi_model, ce_model, params], sort_keys=True, default=str,
        ).encode("utf-8")).hexdigest()

        if st.button("Run grounder", type="primary", disabled=not steps_records or not thresholds_ok):
            try:
                with st.spinner("Grounding steps… (the first run downloads both models, ~3.5 GB)"):
                    st.session_state["grounding"] = _ground(
                        json.dumps(steps_records), json.dumps(clusters_min),
                        bi_model, ce_model, json.dumps(params),
                    )
                    st.session_state["grounding_sig"] = ground_sig
            except Exception as exc:
                st.error(f"Grounding failed: {type(exc).__name__}: {exc}")

        result = st.session_state.get("grounding")
        if result and st.session_state.get("grounding_sig") != ground_sig:
            st.info("Steps, clusters or settings changed since the last run. Run the grounder again to refresh.")
            result = None

        if result:
            st.subheader("3 · Results")
            sgs = result["step_groundings"]
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Steps", len(sgs))
            m2.metric("Grounded", sum(not sg["is_ungrounded"] for sg in sgs))
            m3.metric("Ungrounded", len(result["ungrounded_step_ids"]))
            m4.metric("Ambiguous", len(result["ambiguous_step_ids"]))
            st.caption(f"{result['clusters_scored']} clusters scored · "
                       f"{result['clusters_skipped_no_text']} skipped (no cluster_text) · "
                       f"{result['model_bi_encoder']} → {result['model_cross_encoder']}")

            meta_by_key = {c["fingerprint_key"]: (c.get("metadata") or {}) for c in output["clusters"]}
            count_by_key = {c["fingerprint_key"]: (c.get("aggregate") or {}).get("count") for c in output["clusters"]}

            def _tier(key: str) -> str:
                tier = meta_by_key.get(key, {}).get("tier")
                return getattr(tier, "value", tier) or "—"

            summary = []
            for sg in sgs:
                top = sg["matched_clusters"][0] if sg["matched_clusters"] else None
                label = getattr(top["evidence_label"], "value", top["evidence_label"]) if top else "UNGROUNDED"
                summary.append({
                    "step": sg["step"]["step_id"],
                    "text": sg["step"]["text"],
                    "top evidence": label,
                    "top score": top["score"] if top else sg["top_candidate_score"],
                    "matches": len(sg["matched_clusters"]),
                    "ambiguous": sg["is_ambiguous"],
                    "top cluster": top["cluster_fingerprint_key"] if top else "",
                })
            st.dataframe(pd.DataFrame(summary), hide_index=True, width="stretch")

            for sg in sgs:
                step = sg["step"]
                matches = sg["matched_clusters"]
                if matches:
                    lbl = getattr(matches[0]["evidence_label"], "value", matches[0]["evidence_label"])
                    head = f"{EVIDENCE_ICON.get(lbl, '')} Step {step['step_id']} — {step['text']}"
                else:
                    head = f"🔴 Step {step['step_id']} — {step['text']}"
                if sg["is_ambiguous"]:
                    head += "  ·  ambiguous"
                with st.expander(head):
                    if step.get("source_text") and step["source_text"] != step["text"]:
                        st.caption(f"Source: {step['source_text']}")
                    if not matches:
                        st.warning("Ungrounded: no cluster scored above the NEUTRAL threshold "
                                   f"(best candidate {sg['top_candidate_score']}). The described behaviour "
                                   "may not be visible in this capture.")
                        continue
                    if sg["is_ambiguous"]:
                        st.info("Rank-1 and rank-2 scores are within the ambiguity gap; review both.")
                    st.dataframe(pd.DataFrame([{
                        "rank": m["rank"],
                        "evidence": getattr(m["evidence_label"], "value", m["evidence_label"]),
                        "score": m["score"],
                        "gap to next": m["score_gap"],
                        "bi-encoder": m["bi_encoder_score"],
                        "tier": _tier(m["cluster_fingerprint_key"]),
                        "packets": count_by_key.get(m["cluster_fingerprint_key"]),
                        "fingerprint": m["cluster_fingerprint_key"],
                    } for m in matches]), hide_index=True, width="stretch")
                    for m in matches:
                        st.markdown(f"**#{m['rank']}** `{m['cluster_fingerprint_key']}`")
                        st.text(m["cluster_text"])

            st.markdown("**Mapping** `{step_id: [fingerprint_key, …]}`")
            st.json({sid: [m["fingerprint_key"] for m in ms] for sid, ms in result["grounding_dict"].items()},
                    expanded=False)

            g1, g2, _ = st.columns([1, 1, 4])
            g1.download_button("Download grounding (.json)", json.dumps(result, indent=2, default=str),
                               file_name=f"{base}_grounding.json", mime="application/json")
            g2.download_button("Download steps (.json)", json.dumps(steps_records, indent=2, ensure_ascii=False),
                               file_name=f"extracted_{base}.json", mime="application/json")


upload_tab, evaluator_tab = st.tabs(["Upload & ground", "Evaluator"])
with upload_tab:
    render_upload_tab()
with evaluator_tab:
    render_evaluator_tab()
