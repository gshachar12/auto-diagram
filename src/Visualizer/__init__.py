"""
Visualizer
==========

Turns the actors/steps produced by Step Extractor into a D2 diagram of the
described traffic. Each actor node and each step edge is annotated with its
Evidence Matcher result (resolved endpoint / grounding status / linked
evidence counts) when that data is available, so a single glance shows both
"what the description claims happened" (the raw steps/actors -- this is what
drives the diagram's shape) and "what the packet capture actually backs up"
(the grounding -- this drives each node/edge's color and tooltip).

Public entry point: `generate_diagram()` below.
"""
from Visualizer.visualize import generate_diagram, VisualizerResult

__all__ = ["generate_diagram", "VisualizerResult"]
