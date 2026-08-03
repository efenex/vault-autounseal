"""Regression tests for the transport layer.

These pin the failure that took Vault down on 2026-08-03: an ingress in front
of Vault answered an outage with an HTML 503, ``get_seal_status`` called
``.json()`` on it, and the resulting ``JSONDecodeError`` escaped the main loop.
The process exited 1 and CrashLoopBackOff then held the unsealer down -- with a
backoff that grew on every attempt -- while Vault sat sealed.

The invariant these tests defend is narrow and absolute: **no remote behaviour
may raise out of get_seal_status**. A wrong answer costs one scan cycle; an
exception costs an exponentially growing outage.
"""
import http.server
import importlib.util
import pathlib
import sys
import threading
import types

import pytest

APP_PATH = pathlib.Path(__file__).resolve().parent.parent / "app.py"

NGINX_503 = (
    b"<html><head><title>503 Service Temporarily Unavailable</title></head>"
    b"<body><center><h1>503 Service Temporarily Unavailable</h1></center>"
    b"<hr><center>nginx</center></body></html>"
)


def _load_app():
    """Import app.py with the Kubernetes client stubbed out.

    The module body only imports these; every use is inside functions or the
    ``__main__`` guard, so stubs are enough to exercise the HTTP paths.
    """
    for name in (
        "kubernetes",
        "kubernetes.client",
        "kubernetes.config",
        "kubernetes.client.exceptions",
        "kubernetes.config.config_exception",
        "loguru",
    ):
        sys.modules.setdefault(name, types.ModuleType(name))

    class _NullLogger:
        def __getattr__(self, _):
            return lambda *args, **kwargs: None

    sys.modules["loguru"].logger = _NullLogger()
    sys.modules["kubernetes"].client = sys.modules["kubernetes.client"]
    sys.modules["kubernetes"].config = sys.modules["kubernetes.config"]
    sys.modules["kubernetes.client"].exceptions = types.SimpleNamespace(
        ApiException=Exception
    )
    sys.modules["kubernetes.config"].config_exception = types.SimpleNamespace(
        ConfigException=Exception
    )

    spec = importlib.util.spec_from_file_location("app_under_test", APP_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # Defined under the __main__ guard in production; the seal-status helpers
    # read them as globals.
    module.status_init, module.status_unseal = 0, 1
    module.status_ok, module.status_error = 2, 3
    return module


@pytest.fixture(scope="module")
def app():
    return _load_app()


@pytest.fixture
def responder():
    """Serve a caller-chosen status/content-type/body on localhost."""
    state = {"status": 200, "ctype": "application/json", "body": b"{}"}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(state["status"])
            self.send_header("Content-Type", state["ctype"])
            self.send_header("Content-Length", str(len(state["body"])))
            self.end_headers()
            self.wfile.write(state["body"])

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    state["url"] = f"http://127.0.0.1:{server.server_address[1]}"
    yield state
    server.shutdown()


@pytest.mark.parametrize(
    "status,ctype,body,label",
    [
        (503, "text/html", NGINX_503, "nginx HTML 503 (the 2026-08-03 outage)"),
        (502, "text/html", b"<html>502 Bad Gateway</html>", "HTML 502"),
        (200, "application/json", b"", "empty body, 200"),
        (200, "application/json", b"{truncated", "truncated JSON"),
        (200, "text/plain", b"OK", "plain text 200"),
    ],
)
def test_non_json_never_raises(app, responder, status, ctype, body, label):
    """Anything that is not parseable JSON collapses to None, never an exception."""
    responder.update(status=status, ctype=ctype, body=body)
    assert app.request_json("GET", f"{responder['url']}/v1/sys/seal-status") is None, label


def test_seal_status_degrades_on_html_error_page(app, responder):
    """The exact 2026-08-03 call path returns status_error instead of raising."""
    responder.update(status=503, ctype="text/html", body=NGINX_503)
    assert app.get_seal_status(responder["url"], True) == app.status_error


def test_seal_status_degrades_when_vault_is_gone(app):
    """A refused connection -- pod evicted, not yet rescheduled -- is survivable."""
    assert app.get_seal_status("http://127.0.0.1:1", True) == app.status_error


def test_seal_status_reads_a_healthy_unsealed_vault(app, responder):
    """The happy path still works: this must not be a fix that fails closed."""
    responder.update(
        status=200,
        ctype="application/json",
        body=b'{"initialized": true, "sealed": false}',
    )
    assert app.get_seal_status(responder["url"], True) == app.status_ok


def test_seal_status_detects_a_sealed_vault(app, responder, monkeypatch):
    """A sealed Vault must still trigger the unseal path."""
    responder.update(
        status=200,
        ctype="application/json",
        body=b'{"initialized": true, "sealed": true}',
    )
    monkeypatch.setattr(app, "read_secret", lambda *args: None)
    monkeypatch.setattr(app, "vault_keys", "vault-unseal", raising=False)
    assert app.get_seal_status(responder["url"], True) == app.status_unseal


def test_every_request_is_bounded_by_a_timeout(app):
    """A wedged socket must not hang the scan loop forever.

    This is the silent twin of the crash: an unsealer blocked on a dead
    connection looks alive to Kubernetes while unsealing nothing.
    """
    assert app.HTTP_TIMEOUT > 0
