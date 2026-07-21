#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Implicit-interface extraction.

Python has no enforced interfaces, but every codebase has *implicit* ones:
the set of members of a module (or class) that are actually referenced from
outside that module (or class). This module distills a completed
:class:`~pyan.analyzer.CallGraphVisitor` analysis into a JSON-serializable
"interface model" describing those boundaries:

- per-module member lists, each member annotated with its external consumers,
- aggregated module-to-module edges with the member-level references behind them,
- boundary violations: cross-module access to ``_private`` names, cross-class
  access to private class members, dependency cycles, and advisory findings
  (public members never used externally, oversized public surfaces).

The model is the data source for the ``pyan3 --web`` interface explorer
(see :mod:`pyan.web`), and is usable directly via :func:`create_interface_model`.
"""

from .node import Flavor

__all__ = ["build_interface_model", "create_interface_model"]

# A module whose externally-used surface exceeds this many members gets an
# advisory "wide-interface" finding.
WIDE_INTERFACE_THRESHOLD = 15

# Flavors that represent analysis bookkeeping rather than program objects.
_NON_MEMBER_FLAVORS = (Flavor.SCOPE, Flavor.UNKNOWN)

# Advisory "unused-externally" findings are only reported for these flavors;
# reporting every module-level NAME would drown the signal.
_ADVISORY_FLAVORS = (Flavor.FUNCTION, Flavor.CLASS)


def _is_private_component(name):
    """True for ``_name`` and name-mangled ``__name``, but not dunders."""
    return name.startswith("_") and not (name.startswith("__") and name.endswith("__"))


def _qname_depth(qname):
    """Sort key preferring the most specific (deepest, then longest) qname."""
    return (qname.count("."), qname)


def _tarjan_sccs(adjacency):
    """Return the strongly connected components of *adjacency* (dict node → set of nodes).

    Iterative Tarjan; only components with more than one member are returned
    (single nodes without self-loops are not cycles).
    """
    index_of, lowlink = {}, {}
    on_stack, stack = set(), []
    sccs = []
    counter = [0]

    for root in adjacency:
        if root in index_of:
            continue
        work = [(root, iter(sorted(adjacency.get(root, ()))))]
        index_of[root] = lowlink[root] = counter[0]
        counter[0] += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, successors = work[-1]
            advanced = False
            for succ in successors:
                if succ not in index_of:
                    index_of[succ] = lowlink[succ] = counter[0]
                    counter[0] += 1
                    stack.append(succ)
                    on_stack.add(succ)
                    work.append((succ, iter(sorted(adjacency.get(succ, ())))))
                    advanced = True
                    break
                elif succ in on_stack:
                    lowlink[node] = min(lowlink[node], index_of[succ])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                lowlink[parent] = min(lowlink[parent], lowlink[node])
            if lowlink[node] == index_of[node]:
                component = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == node:
                        break
                if len(component) > 1:
                    sccs.append(sorted(component))
    return sccs


class _ModelBuilder:
    def __init__(self, visitor):
        self.visitor = visitor
        self.known_modules = dict(visitor.module_to_filename)
        # Longest-prefix module lookup, memoized.
        self._modules_by_length = sorted(self.known_modules, key=len, reverse=True)
        self._owner_cache = {}
        # qname → Node for every defined, non-bookkeeping node.
        self.defined = {}
        for node_list in visitor.nodes.values():
            for n in node_list:
                if n.namespace is None or not n.defined or n.flavor in _NON_MEMBER_FLAVORS:
                    continue
                qname = n.get_name()
                prev = self.defined.get(qname)
                if prev is None or Flavor.specificity(n.flavor) > Flavor.specificity(prev.flavor):
                    self.defined[qname] = n
        # class qname → set of ancestor class qnames (from the visitor's MRO),
        # used to exempt subclass access to a base's private members.
        self.class_ancestors = {}
        for cls_node, mro_list in getattr(visitor, "mro", {}).items():
            if cls_node.namespace is None:
                continue
            ancestors = {b.get_name() for b in mro_list[1:] if b.namespace is not None}
            if ancestors:
                self.class_ancestors[cls_node.get_name()] = ancestors
        # target Node → set of consumer Nodes (both defined, both in analyzed modules).
        self.consumers_of = {}
        for consumer, targets in visitor.uses_edges.items():
            cq = consumer.get_name() if consumer.namespace is not None else None
            if cq is None or cq not in self.defined or self.owner_module(cq) is None:
                continue
            for target in targets:
                if target.namespace is None:
                    continue
                tq = target.get_name()
                if tq in self.defined and self.owner_module(tq) is not None and tq != cq:
                    self.consumers_of.setdefault(tq, set()).add(cq)

    def owner_module(self, qname):
        """Return the analyzed module owning *qname*, or None if external."""
        if qname not in self._owner_cache:
            result = None
            for mod in self._modules_by_length:
                if qname == mod or qname.startswith(mod + "."):
                    result = mod
                    break
            self._owner_cache[qname] = result
        return self._owner_cache[qname]

    def owner_class(self, qname):
        """Return the qname of the nearest enclosing class of *qname*, or None."""
        parts = qname.split(".")
        for i in range(len(parts) - 1, 0, -1):
            ancestor = ".".join(parts[:i])
            node = self.defined.get(ancestor)
            if node is not None and node.flavor == Flavor.CLASS:
                return ancestor
        return None

    def _location(self, node):
        # ast.Module has no lineno; everything else in the graph does.
        return node.filename, getattr(node.ast_node, "lineno", None)

    def build(self):
        modules = {
            mod: {"file": filename, "members": [], "surface": 0,
                  "fan_in": set(), "fan_out": set()}
            for mod, filename in self.known_modules.items()
        }
        violations = []
        seen_violations = set()

        def add_violation(kind, severity, message, target, consumer=None, file=None, line=None, key=None):
            key = key or (kind, consumer, target)
            if key in seen_violations:
                return
            seen_violations.add(key)
            violations.append({
                "kind": kind,
                "severity": severity,
                "message": message,
                "target": target,
                "target_module": self.owner_module(target) if target else None,
                "consumer": consumer,
                "consumer_module": self.owner_module(consumer) if consumer else None,
                "file": file,
                "line": line,
            })

        # --- Members and per-member consumer lists -----------------------------
        for qname, node in sorted(self.defined.items()):
            mod = self.owner_module(qname)
            if mod is None or qname == mod:
                continue
            rel_components = qname[len(mod) + 1:].split(".")
            private = any(_is_private_component(c) for c in rel_components)
            owner_class = self.owner_class(qname)
            filename, line = self._location(node)

            external, internal = [], []
            for cq in sorted(self.consumers_of.get(qname, ())):
                cmod = self.owner_module(cq)
                if cmod != mod:
                    external.append({"qname": cq, "module": cmod})
                else:
                    internal.append(cq)

            modules[mod]["members"].append({
                "qname": qname,
                "name": node.name,
                "kind": node.flavor.value,
                "parent": node.namespace,
                "owner_class": owner_class,
                "depth": len(rel_components),
                "private": private,
                "file": filename,
                "line": line,
                "external_consumers": external,
                "internal_consumers": sorted(internal),
            })

            if external:
                modules[mod]["surface"] += 1
                if private:
                    # One finding per consumer module (the same leak often shows
                    # up as both an import and a call site); report the most
                    # specific consumer as the representative.
                    by_consumer_mod = {}
                    for c in external:
                        if owner_class is not None:
                            consumer_class = self.owner_class(c["qname"])
                            if consumer_class and owner_class in self.class_ancestors.get(consumer_class, ()):
                                continue  # subclass using its base's private member
                        by_consumer_mod.setdefault(c["module"], []).append(c["qname"])
                    for cmod, consumer_qnames in sorted(by_consumer_mod.items()):
                        rep = max(consumer_qnames, key=_qname_depth)
                        add_violation(
                            "private-cross-module", "high",
                            f"{cmod} reaches into {mod}'s private member {qname}",
                            target=qname, consumer=rep, file=filename, line=line,
                            key=("private-cross-module", cmod, qname),
                        )

            # Private class member used from the same module but outside the class.
            # Subclass access to a base class's private member is conventional
            # Python and exempt (checked against the analyzed MRO).
            if owner_class is not None and _is_private_component(node.name):
                for cq in internal:
                    if cq == owner_class or cq.startswith(owner_class + "."):
                        continue
                    consumer_class = self.owner_class(cq)
                    if consumer_class and owner_class in self.class_ancestors.get(consumer_class, ()):
                        continue
                    cfile, cline = self._location(self.defined[cq])
                    add_violation(
                        "private-cross-class", "medium",
                        f"{cq} accesses {owner_class}'s private member {node.name} from outside the class",
                        target=qname, consumer=cq, file=cfile, line=cline,
                    )

            if (not external and not private and len(rel_components) == 1
                    and node.flavor in _ADVISORY_FLAVORS):
                add_violation(
                    "unused-externally", "info",
                    f"public {node.flavor.value} {qname} is never used outside {mod} — "
                    "candidate for a leading underscore (or it is an entry point)",
                    target=qname, file=filename, line=line,
                )

        # --- Aggregated module→module edges ------------------------------------
        edge_refs = {}
        for tq, consumer_set in self.consumers_of.items():
            tmod = self.owner_module(tq)
            tnode = self.defined[tq]
            rel = tq[len(tmod) + 1:] if tq != tmod else ""
            private = any(_is_private_component(c) for c in rel.split(".")) if rel else False
            _, tline = self._location(tnode)
            for cq in consumer_set:
                cmod = self.owner_module(cq)
                if cmod == tmod:
                    continue
                modules[cmod]["fan_out"].add(tmod)
                modules[tmod]["fan_in"].add(cmod)
                edge_refs.setdefault((cmod, tmod), []).append({
                    "from": cq, "to": tq, "private": private, "line": tline,
                })

        module_edges = []
        for (src, tgt), refs in sorted(edge_refs.items()):
            refs.sort(key=lambda r: (r["to"], r["from"]))
            module_edges.append({"source": src, "target": tgt, "weight": len(refs), "refs": refs})

        # --- Cycles ------------------------------------------------------------
        adjacency = {}
        for (src, tgt) in edge_refs:
            adjacency.setdefault(src, set()).add(tgt)
            adjacency.setdefault(tgt, set())
        cycles = _tarjan_sccs(adjacency)
        for component in cycles:
            add_violation(
                "dependency-cycle", "medium",
                "dependency cycle: " + " ↔ ".join(component),
                target=component[0],
            )

        # --- Advisories on module shape ----------------------------------------
        for mod, record in modules.items():
            if record["surface"] > WIDE_INTERFACE_THRESHOLD:
                add_violation(
                    "wide-interface", "info",
                    f"{mod} exposes {record['surface']} externally-used members "
                    f"(threshold {WIDE_INTERFACE_THRESHOLD}) — consider splitting or narrowing",
                    target=mod, file=record["file"],
                )
            record["fan_in"] = sorted(record["fan_in"])
            record["fan_out"] = sorted(record["fan_out"])
            record["members"].sort(key=lambda m: (m["owner_class"] or "", m["qname"]))

        severity_rank = {"high": 0, "medium": 1, "info": 2}
        violations.sort(key=lambda v: (severity_rank[v["severity"]], v["kind"], v["target"]))

        return {
            "modules": modules,
            "module_edges": module_edges,
            "cycles": cycles,
            "violations": violations,
            "summary": {
                "module_count": len(modules),
                "violation_counts": {
                    sev: sum(1 for v in violations if v["severity"] == sev)
                    for sev in ("high", "medium", "info")
                },
            },
        }


def build_interface_model(visitor):
    """Build the interface model (a JSON-serializable dict) from a completed analysis."""
    return _ModelBuilder(visitor).build()


def create_interface_model(filenames="**/*.py", root=None, exclude=None,
                           namespace_constructors=None, logger=None):
    """Analyze *filenames* and return the interface model.

    Convenience wrapper mirroring :func:`pyan.create_callgraph`'s source handling.
    """
    from .analyzer import CallGraphVisitor
    from .anutils import expand_sources

    if isinstance(filenames, str):
        filenames = [filenames]
    filenames = expand_sources(filenames, exclude=exclude)
    visitor = CallGraphVisitor(filenames, root=root, logger=logger,
                               namespace_constructors=namespace_constructors)
    return build_interface_model(visitor)
