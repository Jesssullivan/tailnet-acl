"""Behavioral proof for public output, immutable source, and conditional updates."""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import acl_validate
import ci_preflight
import policy_api
import policy_source
import push

PRIVATE = "private-member@example.invalid"
BASE = {"acls": [], "hosts": {PRIVATE: "100.64.0.1"}}
CANDIDATE = {"acls": [], "hosts": {PRIVATE: "100.64.0.1", "new": "100.64.0.2"}}


class ConditionalPromotionTest(unittest.TestCase):
    def run_promotion(self, reads, post_error=None, live_digest=None, candidate_digest=None, dry_run=False, grammar_error=None):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output), mock.patch.object(
            push, "fetch_live_acl", side_effect=reads
        ) as read, mock.patch.object(push, "push_acl", side_effect=post_error) as write, mock.patch.object(
            push, "validate_candidate", side_effect=grammar_error
        ) as grammar:
            error = None
            try:
                push.promote("credential-not-for-output", CANDIDATE,
                             live_digest or policy_source.canonical_digest(BASE),
                             candidate_digest or policy_source.canonical_digest(CANDIDATE), dry_run=dry_run)
            except policy_source.PolicyError as exc:
                error = str(exc)
        if write.call_count:
            grammar.assert_called_once_with("credential-not-for-output", CANDIDATE, prove=True)
        self.assertNotIn(PRIVATE, output.getvalue())
        self.assertNotIn("100.64.0.1", output.getvalue())
        self.assertNotIn("credential-not-for-output", output.getvalue())
        return error, read.call_count, write.call_count, write.call_args

    def test_exact_baseline_posts_once_then_checks_fresh_read(self):
        error, reads, writes, args = self.run_promotion([(BASE, '"etag"'), (CANDIDATE, '"after"')])
        self.assertIsNone(error)
        self.assertEqual((reads, writes), (2, 1))
        self.assertEqual(args.args[2], '"etag"')

    def test_already_candidate_is_idempotent_without_post(self):
        error, reads, writes, _ = self.run_promotion([(CANDIDATE, '"etag"')])
        self.assertIsNone(error)
        self.assertEqual((reads, writes), (1, 0))

    def test_unexpected_live_drift_never_posts(self):
        drift = copy.deepcopy(BASE)
        drift["unexpected-private-key"] = PRIVATE
        error, reads, writes, _ = self.run_promotion([(drift, '"etag"')])
        self.assertIn("baseline", error)
        self.assertEqual((reads, writes), (1, 0))

    def test_missing_or_weak_etag_never_posts(self):
        for etag in ("", 'W/"etag"', "bad\nheader", "*", '"etag', 'etag"'):
            with self.subTest(etag=repr(etag)):
                error, reads, writes, _ = self.run_promotion([(BASE, etag)])
                self.assertIn("ETag", error)
                self.assertEqual((reads, writes), (1, 0))

    def test_candidate_digest_mismatch_never_reads_or_posts(self):
        error, reads, writes, _ = self.run_promotion([], candidate_digest="f" * 64)
        self.assertIn("candidate", error)
        self.assertEqual((reads, writes), (0, 0))

    def test_failed_grammar_proof_never_posts(self):
        error, reads, writes, _ = self.run_promotion([(BASE, '"etag"')], grammar_error=policy_source.PolicyError("grammar proof absent"))
        self.assertIn("grammar", error)
        self.assertEqual((reads, writes), (1, 0))

    def test_malformed_utf8_canary_prevents_actual_policy_post(self):
        with mock.patch.object(push, "fetch_live_acl", return_value=(BASE, '"etag"')), mock.patch.object(
            acl_validate, "post_validate", return_value=(200, b'{"message":"\xff"}')
        ) as checker, mock.patch.object(push, "push_acl") as write, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(policy_source.PolicyError):
                push.promote("not-printed", CANDIDATE, policy_source.canonical_digest(BASE), policy_source.canonical_digest(CANDIDATE))
        checker.assert_called_once()
        write.assert_not_called()

    def test_412_is_not_retried(self):
        error, reads, writes, _ = self.run_promotion([(BASE, '"etag"')], policy_source.PolicyError("API request failed (HTTP 412)"))
        self.assertIn("412", error)
        self.assertEqual((reads, writes), (1, 1))

    def test_post_timeout_is_not_retried(self):
        error, reads, writes, _ = self.run_promotion([(BASE, '"etag"')], policy_source.PolicyError("API request failed (transport or timeout)"))
        self.assertIn("timeout", error)
        self.assertEqual((reads, writes), (1, 1))

    def test_post_read_mismatch_is_not_success(self):
        error, reads, writes, _ = self.run_promotion([(BASE, '"etag"'), (BASE, '"after"')])
        self.assertIn("post-write", error)
        self.assertEqual((reads, writes), (2, 1))

    def test_dry_run_verifies_baseline_without_post(self):
        error, reads, writes, _ = self.run_promotion([(BASE, '"etag"')], dry_run=True)
        self.assertIsNone(error)
        self.assertEqual((reads, writes), (1, 0))


class BoundedHttpTest(unittest.TestCase):
    def test_validator_preserves_raw_bytes_for_strict_decoding(self):
        raw = b'{"message":"\xff"}'
        with mock.patch.object(acl_validate, "request_bytes", return_value=(200, raw, "")):
            self.assertEqual(acl_validate.post_validate("not-printed", BASE), (200, raw))

    def test_real_trickle_body_is_interrupted_by_elapsed_deadline(self):
        stop = threading.Event()
        class TrickleHandler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "1024")
                self.end_headers()
                while not stop.wait(0.02):
                    try:
                        self.wfile.write(b"x")
                        self.wfile.flush()
                    except OSError:
                        break
        server = HTTPServer(("127.0.0.1", 0), TrickleHandler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            request = policy_api.urllib.request.Request(f"http://127.0.0.1:{server.server_port}/")
            started = time.monotonic()
            with mock.patch.object(policy_api, "TIMEOUT_SECONDS", 0.2):
                with self.assertRaises(policy_source.PolicyError) as caught:
                    policy_api.request_bytes(request)
            elapsed = time.monotonic() - started
            self.assertIn("elapsed deadline", str(caught.exception))
            self.assertLess(elapsed, 0.8)
        finally:
            stop.set()
            server.shutdown()
            server.server_close()
            worker.join(timeout=1)
        self.assertFalse(worker.is_alive())

    def test_active_caller_timer_is_preserved_and_request_refused(self):
        with mock.patch.object(policy_api.signal, "getitimer", return_value=(10.0, 0.0)), mock.patch.object(
            policy_api.signal, "setitimer"
        ) as timer, mock.patch.object(policy_api.OPENER, "open") as request:
            with self.assertRaises(policy_source.PolicyError):
                policy_api.fetch_live_acl("not-printed")
            timer.assert_not_called()
            request.assert_not_called()

    def test_non_main_thread_refuses_before_request(self):
        with mock.patch.object(policy_api.threading, "current_thread", return_value=object()), mock.patch.object(policy_api.OPENER, "open") as request:
            with self.assertRaises(policy_source.PolicyError):
                policy_api.fetch_live_acl("not-printed")
            request.assert_not_called()

    def test_deadline_restores_signal_handler_and_clears_timer(self):
        previous = signal.getsignal(signal.SIGALRM)
        with policy_api.elapsed_deadline(1):
            pass
        self.assertEqual(signal.getsignal(signal.SIGALRM), previous)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_oversize_body_is_refused(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b"x" * 9
        with mock.patch.object(policy_api, "MAX_RESPONSE_BYTES", 8), mock.patch.object(policy_api.OPENER, "open", return_value=response):
            with self.assertRaises(policy_source.PolicyError) as caught:
                policy_api.fetch_live_acl("not-printed")
        self.assertIn("size limit", str(caught.exception))

    def test_401_403_412_bodies_are_not_in_exceptions_or_preflight(self):
        for status in (401, 403, 412):
            with self.subTest(status=status):
                error = urllib.error.HTTPError("https://api.tailscale.com/", status, PRIVATE, {}, io.BytesIO(PRIVATE.encode()))
                with mock.patch.object(policy_api.OPENER, "open", side_effect=error):
                    with self.assertRaises(policy_source.PolicyError) as caught:
                        policy_api.fetch_live_acl("not-printed")
                self.assertEqual(str(caught.exception), f"API request failed (HTTP {status})")
                output = io.StringIO()
                with mock.patch.object(ci_preflight, "resolve_bearer", return_value="not-printed"), mock.patch.object(
                    ci_preflight, "fetch_live_acl", side_effect=caught.exception
                ), contextlib.redirect_stderr(output):
                    self.assertEqual(ci_preflight.main(), 1)
                self.assertNotIn(PRIVATE, output.getvalue())

    def test_malformed_response_does_not_echo_body(self):
        with self.assertRaises(policy_source.PolicyError) as caught:
            policy_api.parse_object(PRIVATE.encode())
        self.assertEqual(str(caught.exception), "API response is malformed")

    def test_http_200_error_object_is_not_policy_read_success(self):
        with mock.patch.object(policy_api, "request_bytes", return_value=(200, json.dumps({"message": PRIVATE}).encode(), '"etag"')):
            with self.assertRaises(policy_source.PolicyError) as caught:
                policy_api.fetch_live_acl("not-printed")
        self.assertNotIn(PRIVATE, str(caught.exception))

    def test_timeout_is_bounded_and_sanitized(self):
        with mock.patch.object(policy_api.OPENER, "open", side_effect=TimeoutError(PRIVATE)) as request:
            with self.assertRaises(policy_source.PolicyError) as caught:
                policy_api.fetch_live_acl("not-printed")
        self.assertNotIn(PRIVATE, str(caught.exception))
        self.assertEqual(request.call_args.kwargs["timeout"], 20)

    def test_invalid_authorization_header_diagnostic_is_sanitized(self):
        with mock.patch.object(policy_api.OPENER, "open", side_effect=ValueError("Invalid header value: " + PRIVATE)):
            with self.assertRaises(policy_source.PolicyError) as caught:
                policy_api.fetch_live_acl("not-printed")
        self.assertEqual(str(caught.exception), "API request failed (invalid request or response)")

    def test_post_carries_if_match_and_has_timeout(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.side_effect = [b"{}", b""]
        with mock.patch.object(policy_api.OPENER, "open", return_value=response) as request:
            policy_api.push_acl("not-printed", CANDIDATE, '"etag"')
        self.assertEqual(request.call_args.args[0].get_header("If-match"), '"etag"')
        self.assertEqual(request.call_args.kwargs["timeout"], 20)

    def test_redirects_are_refused_without_forwarding_authorization(self):
        handlers = [handler for handler in policy_api.OPENER.handlers if isinstance(handler, policy_api._NoRedirect)]
        self.assertEqual(len(handlers), 1)
        request = policy_api.urllib.request.Request("https://api.tailscale.com/", headers={"Authorization": "Bearer " + PRIVATE})
        for destination in ("https://api.tailscale.com/elsewhere", "https://untrusted.invalid/"):
            with self.subTest(destination=destination), mock.patch.object(policy_api.urllib.request, "Request") as next_request:
                with self.assertRaises(policy_source.PolicyError) as caught:
                    handlers[0].redirect_request(request, None, 302, "", {}, destination)
                next_request.assert_not_called()
                self.assertEqual(str(caught.exception), "API redirect refused")

    def test_wrong_falsy_validation_types_fail_without_disclosure(self):
        for field, value in (("message", 0), ("message", False), ("message", []), ("message", {}),
                             ("data", 0), ("data", False), ("data", {}), ("data", "")):
            with self.subTest(field=field, value=value):
                ok, problems = acl_validate.interpret(200, json.dumps({field: value}))
                self.assertFalse(ok)
                self.assertTrue(any("type" in problem for problem in problems))
        for valid in ({"message": None, "data": None}, {"message": "", "data": []}):
            self.assertEqual(acl_validate.interpret(200, json.dumps(valid)), (True, []))

    def test_all_nonempty_validation_data_fails_without_disclosure(self):
        for data in ([{}], [PRIVATE], {PRIVATE: PRIVATE}):
            ok, problems = acl_validate.interpret(200, json.dumps({"data": data}))
            self.assertFalse(ok)
            self.assertNotIn(PRIVATE, json.dumps(problems))


class SourceAndWorkflowTest(unittest.TestCase):
    def test_strict_json_rejects_duplicates_nonfinite_and_overflow(self):
        for text in ('{"acls":[],"acls":[]}', '{"x":{"a":1,"a":2}}', '{"x":NaN}', '{"x":Infinity}', '{"x":-Infinity}', '{"x":1e999}'):
            with self.subTest(text=text):
                with self.assertRaises(policy_source.PolicyError):
                    policy_source.strict_json_loads(text)
                with self.assertRaises(policy_source.PolicyError):
                    policy_api.parse_object(text)
                self.assertFalse(acl_validate.interpret(200, text)[0])
        with self.assertRaises(policy_source.PolicyError):
            policy_source.canonical_digest({"x": float("nan")})

    def test_compiler_subprocess_does_not_inherit_credentials(self):
        with mock.patch.dict(os.environ, {"TAILSCALE_API_KEY": PRIVATE, "GITHUB_TOKEN": PRIVATE}), mock.patch.object(
            policy_source.subprocess, "run", return_value=mock.Mock(stdout=b"ok")
        ) as run:
            policy_source._run(["dhall", "--version"], ROOT)
        environment = run.call_args.kwargs["env"]
        self.assertEqual(set(environment), {"PATH", "LANG", "LC_ALL", "XDG_CACHE_HOME"})
        self.assertNotIn(PRIVATE, json.dumps(environment))

    def test_parser_guard_rejects_external_environment_and_escaping_imports(self):
        gitdir = ROOT / ".git"
        with tempfile.TemporaryDirectory(prefix="acl-import-test-", dir=gitdir) as directory:
            root = Path(directory)
            source = root / "policy.dhall"
            for expression in ('env:TAILNET_REVIEW_SENTINEL_NOT_PRESENT_20260909 as Text', 'https://invalid.example/policy.dhall', '/private/policy.dhall', '~/policy.dhall', '../outside.dhall', './missing.dhall'):
                source.write_text(expression)
                with self.subTest(expression=expression), self.assertRaises(policy_source.PolicyError):
                    policy_source.check_local_imports(root)
            source.write_text('./local.dhall')
            (root / "local.dhall").write_text('True')
            policy_source.check_local_imports(root)

    def test_invalid_missing_and_zero_baseline_refs_fail_before_lookup(self):
        for value in (None, "", "0" * 40, "main", "--help", "g" * 40):
            with self.subTest(value=value), mock.patch.object(policy_source, "_run") as lookup:
                with self.assertRaises(policy_source.PolicyError):
                    policy_source.compile_revision(value)
                lookup.assert_not_called()

    def test_stale_generated_artifact_is_ignored_by_real_committed_compilation(self):
        artifact = ROOT / "generated/policy.json"
        previous = artifact.read_bytes() if artifact.exists() else None
        original_read_text = Path.read_text
        def guarded_read(path, *args, **kwargs):
            if path == artifact:
                self.fail("compiled candidate read generated/policy.json")
            return original_read_text(path, *args, **kwargs)
        with mock.patch.object(Path, "read_text", guarded_read):
            policy = policy_source.compile_revision(policy_source.head_revision())
        self.assertIn("acls", policy)
        if previous is not None:
            self.assertEqual(artifact.read_bytes(), previous)

    def test_public_summary_omits_unknown_section_names_and_private_values(self):
        live = {**BASE, PRIVATE: {"nested": PRIVATE}}
        result = policy_source.public_summary(live, CANDIDATE)
        self.assertTrue(result["other_sections_changed"])
        self.assertNotIn(PRIVATE, json.dumps(result))

    def test_trusted_driver_keeps_existing_promotion_guard(self):
        import policy_ci
        with mock.patch.object(policy_ci, "trusted_context", return_value=("a" * 40, "b" * 40)), mock.patch.object(
            policy_ci, "_run"
        ), mock.patch.object(policy_ci, "compile_revision", side_effect=[{"acls": []}, {"acls": [1]}]), mock.patch.object(
            policy_ci, "resolve_oidc", return_value="reader-or-writer-in-memory"
        ), mock.patch.object(policy_ci, "promote") as promote:
            policy_ci.run("writer")
        promote.assert_called_once_with("reader-or-writer-in-memory", {"acls": [1]}, policy_source.canonical_digest({"acls": []}), policy_source.canonical_digest({"acls": [1]}))


if __name__ == "__main__":
    unittest.main()
