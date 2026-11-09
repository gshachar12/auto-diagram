"""
PAnGEA Dataset Creator.

  Responsibility: build and run the claim-verification dataset -- sources,
  claims, (claim x PCAP) pairs, prompt variants, model runs and the analysis
  over the stored responses. It is the experiment harness, not part of the
  diagram pipeline.

  Deliberately independent of Preprocessor/ (the clustering pipeline). The
  experiment measures whether a panel of models can verify claims against a
  capture; feeding it the Preprocessor's clusters would make the labels
  depend on the algorithm under test. Clusters may be read later, by the
  analysis only, as a sensitivity comparison -- never by a solver model.

  Two invariants shape every module here:

    Raw data is immutable   -- sources, claims, pairs, prompts and model
                               calls are append-only. A correction is a new
                               version that supersedes the old row; nothing
                               is overwritten or deleted. Enforced in SQLite
                               by triggers, not by convention (storage/db.py).
    Derived data is recomputable -- every metric is computed by analysis code
                               from stored responses, never by a model, and
                               re-running it on the same rows must reproduce
                               the same numbers.
"""
from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
