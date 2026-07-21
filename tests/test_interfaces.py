"""Tests for the implicit-interface extraction layer (pyan.interfaces)."""

import json

from pyan.analyzer import CallGraphVisitor
from pyan.interfaces import build_interface_model

# A small package with deliberate boundary characteristics:
# - core exposes a public class and function, plus privates.
# - app consumes core's public surface AND reaches into a private (violation).
# - core.helpers accesses a private class member from outside the class,
#   within the same module (cross-class violation).
# - util and core import each other (dependency cycle).
# - core.unused_public is never used externally (advisory).

CORE = """\
import util

class Engine:
    def start(self):
        return self._ignite()

    def _ignite(self):
        return util.spark()

def make_engine():
    return Engine()

def unused_public():
    pass

def _internal_helper():
    pass

class Panel:
    def poke(self):
        return Engine._ignite(make_engine())

class Turbo(Engine):
    def boost(self):
        return Engine._ignite(self)
"""

UTIL = """\
import core

def spark():
    return 1

def build():
    return core.make_engine()
"""

APP = """\
import core

def run():
    e = core.make_engine()
    e.start()
    return core._internal_helper()
"""


def analyze():
    v = CallGraphVisitor.from_sources([(CORE, "core"), (UTIL, "util"), (APP, "app")])
    return build_interface_model(v)


class TestModel:
    def test_modules_present(self):
        model = analyze()
        assert set(model["modules"]) == {"core", "util", "app"}

    def test_json_serializable(self):
        json.dumps(analyze())

    def test_exposed_members_have_external_consumers(self):
        model = analyze()
        members = {m["qname"]: m for m in model["modules"]["core"]["members"]}
        make_engine = members["core.make_engine"]
        consumer_modules = {c["module"] for c in make_engine["external_consumers"]}
        assert consumer_modules == {"util", "app"}
        assert model["modules"]["core"]["surface"] >= 2  # make_engine + _internal_helper at least

    def test_internal_use_is_not_external(self):
        model = analyze()
        members = {m["qname"]: m for m in model["modules"]["core"]["members"]}
        ignite = members["core.Engine._ignite"]
        # start() and Panel.poke() use it from within core; app does not reach it.
        assert ignite["external_consumers"] == []
        assert "core.Engine.start" in ignite["internal_consumers"]

    def test_member_metadata(self):
        model = analyze()
        members = {m["qname"]: m for m in model["modules"]["core"]["members"]}
        start = members["core.Engine.start"]
        assert start["kind"] == "method"
        assert start["owner_class"] == "core.Engine"
        assert start["private"] is False
        assert start["line"] is not None
        assert members["core.Engine._ignite"]["private"] is True

    def test_fan_in_fan_out(self):
        model = analyze()
        assert model["modules"]["core"]["fan_in"] == ["app", "util"]
        assert "util" in model["modules"]["core"]["fan_out"]


class TestViolations:
    def kinds(self, model):
        return {(v["kind"], v.get("consumer"), v["target"]) for v in model["violations"]}

    def test_private_cross_module(self):
        model = analyze()
        vios = [v for v in model["violations"] if v["kind"] == "private-cross-module"]
        assert any(v["target"] == "core._internal_helper" and v["consumer_module"] == "app"
                   for v in vios)
        assert all(v["severity"] == "high" for v in vios)

    def test_private_cross_class(self):
        model = analyze()
        vios = [v for v in model["violations"] if v["kind"] == "private-cross-class"]
        assert any(v["target"] == "core.Engine._ignite" and v["consumer"] == "core.Panel.poke"
                   for v in vios)

    def test_subclass_access_to_base_private_is_exempt(self):
        model = analyze()
        vios = [v for v in model["violations"] if v["kind"] == "private-cross-class"]
        # Turbo inherits Engine, so Turbo.boost using Engine._ignite is conventional.
        assert not any(v["consumer"] == "core.Turbo.boost" for v in vios)

    def test_private_cross_module_deduped_per_consumer_module(self):
        # app references core._internal_helper via both the import machinery and
        # the call site; only one finding per consumer module should remain.
        model = analyze()
        vios = [v for v in model["violations"]
                if v["kind"] == "private-cross-module" and v["target"] == "core._internal_helper"]
        assert len(vios) == 1
        assert vios[0]["consumer_module"] == "app"

    def test_dependency_cycle(self):
        model = analyze()
        assert ["core", "util"] in model["cycles"]
        assert any(v["kind"] == "dependency-cycle" for v in model["violations"])

    def test_unused_externally_advisory(self):
        model = analyze()
        vios = [v for v in model["violations"] if v["kind"] == "unused-externally"]
        assert any(v["target"] == "core.unused_public" for v in vios)
        # Privates and used members must not be flagged.
        targets = {v["target"] for v in vios}
        assert "core._internal_helper" not in targets
        assert "core.make_engine" not in targets

    def test_summary_counts_match(self):
        model = analyze()
        counts = model["summary"]["violation_counts"]
        for sev in ("high", "medium", "info"):
            assert counts[sev] == sum(1 for v in model["violations"] if v["severity"] == sev)


class TestModuleEdges:
    def test_edges_aggregate_refs(self):
        model = analyze()
        edges = {(e["source"], e["target"]): e for e in model["module_edges"]}
        assert ("app", "core") in edges
        app_core = edges[("app", "core")]
        assert app_core["weight"] == len(app_core["refs"]) >= 2
        assert any(r["to"] == "core._internal_helper" and r["private"] for r in app_core["refs"])

    def test_no_self_edges(self):
        model = analyze()
        assert all(e["source"] != e["target"] for e in model["module_edges"])
