#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Local web UI for exploring implicit interfaces (``pyan3 --web``).

Serves a single-page interface explorer (``webui.html``) backed by a small
JSON API. Stdlib-only (``http.server``); binds to localhost.

Endpoints:

- ``GET /`` — the UI.
- ``GET /api/model`` — the interface model (analyzed on first request, then cached).
- ``POST /api/reanalyze`` — re-expand the source globs, re-run the analysis, and
  return the fresh model. This is the "I refactored, show me the difference" button.
- ``GET /api/source?file=F&line=N`` — a source snippet around line N. Only files
  that appeared in the last analysis may be read.

Analysis errors (e.g. a syntax error introduced mid-refactor) are reported as
JSON with HTTP 500 rather than killing the server, so the edit → re-analyze
loop survives broken intermediate states.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import threading
import time
from urllib.parse import parse_qs, urlparse

from .analyzer import CallGraphVisitor
from .anutils import expand_sources
from .interfaces import build_interface_model

__all__ = ["InterfaceServer", "serve"]

SNIPPET_CONTEXT = 12  # lines of context on each side in /api/source


class InterfaceServer:
    """Owns the analysis state; re-runs it on demand.

    *patterns* are the original CLI glob patterns (not the expanded file list),
    so files added after startup are picked up by re-analysis.
    """

    def __init__(self, patterns, root=None, exclude=None, namespace_constructors=None, logger=None):
        self.patterns = patterns
        self.root = root
        self.exclude = exclude
        self.namespace_constructors = namespace_constructors
        self.logger = logger
        self._lock = threading.Lock()
        self._model = None
        self._allowed_files = set()

    def get_model(self, force=False):
        """Return the interface model, analyzing (or re-analyzing) as needed."""
        with self._lock:
            if self._model is None or force:
                started = time.time()
                filenames = [os.path.abspath(fn)
                             for fn in expand_sources(self.patterns, exclude=self.exclude)]
                if not filenames:
                    raise FileNotFoundError(
                        "No files found matching: " + " ".join(self.patterns))
                visitor = CallGraphVisitor(filenames, root=self.root, logger=self.logger,
                                           namespace_constructors=self.namespace_constructors)
                model = build_interface_model(visitor)
                model["analysis"] = {
                    "file_count": len(filenames),
                    "duration_s": round(time.time() - started, 2),
                    "analyzed_at": time.strftime("%H:%M:%S"),
                }
                self._model = model
                self._allowed_files = {os.path.abspath(f) for f in filenames}
            return self._model

    def get_snippet(self, filename, line):
        """Return a source snippet around *line*; only analyzed files are readable."""
        path = os.path.abspath(filename)
        with self._lock:
            allowed = path in self._allowed_files
        if not allowed:
            raise PermissionError(f"{filename} was not part of the last analysis")
        with open(path, encoding="utf-8", errors="replace") as f:
            all_lines = f.read().splitlines()
        line = max(1, min(line, len(all_lines)))
        start = max(1, line - SNIPPET_CONTEXT)
        end = min(len(all_lines), line + SNIPPET_CONTEXT)
        return {
            "file": filename,
            "focus": line,
            "start": start,
            "lines": all_lines[start - 1:end],
        }


class _Handler(BaseHTTPRequestHandler):
    server_version = "pyan-web"
    # Set by serve():
    interface_server = None
    ui_html = b""

    def _send(self, status, content_type, body):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, payload, status=200):
        self._send(status, "application/json; charset=utf-8",
                   json.dumps(payload).encode("utf-8"))

    def _send_error_json(self, exc, status=500):
        self._send_json({"error": f"{type(exc).__name__}: {exc}"}, status=status)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8", self.ui_html)
        elif url.path == "/api/model":
            try:
                self._send_json(self.interface_server.get_model())
            except Exception as exc:  # analysis must not kill the server
                self._send_error_json(exc)
        elif url.path == "/api/source":
            query = parse_qs(url.query)
            try:
                filename = query["file"][0]
                line = int(query.get("line", ["1"])[0])
                self._send_json(self.interface_server.get_snippet(filename, line))
            except PermissionError as exc:
                self._send_error_json(exc, status=403)
            except (KeyError, ValueError) as exc:
                self._send_error_json(exc, status=400)
            except Exception as exc:
                self._send_error_json(exc)
        else:
            self._send_json({"error": "not found"}, status=404)

    def do_POST(self):
        if urlparse(self.path).path == "/api/reanalyze":
            try:
                self._send_json(self.interface_server.get_model(force=True))
            except Exception as exc:
                self._send_error_json(exc)
        else:
            self._send_json({"error": "not found"}, status=404)

    def log_message(self, format, *args):  # noqa: A002 (stdlib signature)
        if self.interface_server.logger:
            self.interface_server.logger.debug("web: " + format % args)


def serve(patterns, root=None, exclude=None, namespace_constructors=None,
          port=8765, open_browser=True, logger=None):
    """Analyze *patterns* and serve the interface explorer on localhost:*port*.

    Blocks until interrupted (Ctrl+C).
    """
    iserver = InterfaceServer(patterns, root=root, exclude=exclude,
                              namespace_constructors=namespace_constructors, logger=logger)
    with open(os.path.join(os.path.dirname(__file__), "webui.html"), "rb") as f:
        ui_html = f.read()

    handler = type("BoundHandler", (_Handler,),
                   {"interface_server": iserver, "ui_html": ui_html})
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    url = f"http://127.0.0.1:{httpd.server_address[1]}/"
    print(f"pyan interface explorer: {url}  (Ctrl+C to stop)")

    # Warm the model in the background so the first page load is snappy
    # but startup errors still surface in the terminal.
    def warm():
        try:
            iserver.get_model()
        except Exception as exc:
            print(f"analysis error (the UI will show details): {exc}")

    threading.Thread(target=warm, daemon=True).start()

    if open_browser:
        import webbrowser
        threading.Timer(0.3, webbrowser.open, args=(url,)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return url
