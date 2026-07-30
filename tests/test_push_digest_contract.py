import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

SPEC = importlib.util.spec_from_file_location("tailnet_acl_push", SCRIPTS / "push.py")
assert SPEC is not None and SPEC.loader is not None
PUSH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUSH)


class Response:
    def __init__(
        self,
        payload: dict,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.payload = payload
        self.headers = headers or {}

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode()


class PushDigestContractTest(unittest.TestCase):
    def test_digest_is_stable_across_mapping_order(self) -> None:
        left = {"tagOwners": {"tag:b": ["b"], "tag:a": ["a"]}, "acls": []}
        right = {"acls": [], "tagOwners": {"tag:a": ["a"], "tag:b": ["b"]}}
        self.assertEqual(PUSH.policy_sha256(left), PUSH.policy_sha256(right))

    def test_digest_preserves_authoritative_list_order(self) -> None:
        left = {"acls": [{"src": ["a", "b"], "dst": ["c"], "action": "accept"}]}
        right = {"acls": [{"src": ["b", "a"], "dst": ["c"], "action": "accept"}]}
        self.assertNotEqual(PUSH.policy_sha256(left), PUSH.policy_sha256(right))

    def test_receipt_contains_only_non_secret_plan_material(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            PUSH.write_receipt(
                path,
                source_sha="c" * 40,
                pre_write_etag='"pre"',
                pre_policy_sha256="a" * 64,
                local_sha256="b" * 64,
                post_write_etag=None,
                post_policy_sha256=None,
                write_attempted=False,
                outcome="plan_changes",
                changes=["~ grants: 9 -> 10 (+1)"],
            )
            receipt = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(
            receipt,
            {
                "changed": True,
                "changes": ["~ grants: 9 -> 10 (+1)"],
                "local_policy_sha256": "b" * 64,
                "outcome": "plan_changes",
                "post_policy_sha256": None,
                "post_write_etag": None,
                "pre_policy_sha256": "a" * 64,
                "pre_write_etag": '"pre"',
                "source_sha": "c" * 40,
                "tailnet": "taila4c78d.ts.net",
                "write_attempted": False,
            },
        )

    def test_failed_atomic_receipt_replace_preserves_prior_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            prior = '{"outcome":"write_attempt_pending_reconciliation"}\n'
            path.write_text(prior, encoding="utf-8")
            with mock.patch.object(
                PUSH.os,
                "replace",
                side_effect=OSError("simulated replace failure"),
            ):
                with self.assertRaisesRegex(OSError, "replace failure"):
                    PUSH.write_receipt(
                        path,
                        source_sha="c" * 40,
                        pre_write_etag='"pre"',
                        pre_policy_sha256="a" * 64,
                        local_sha256="b" * 64,
                        post_write_etag='"post"',
                        post_policy_sha256="b" * 64,
                        write_attempted=True,
                        outcome="write_accepted_reconciled",
                        changes=[],
                    )
            self.assertEqual(path.read_text(encoding="utf-8"), prior)

    def test_receipt_fsyncs_file_then_replace_then_parent_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            temporary = path.with_name(f".{path.name}.tmp")
            temporary.write_text("stale temporary", encoding="utf-8")
            temporary.chmod(0o644)
            events = []
            real_fsync = PUSH.os.fsync
            real_replace = PUSH.os.replace

            def fsync(descriptor: int) -> None:
                events.append("fsync")
                real_fsync(descriptor)

            def replace(source: object, destination: object) -> None:
                events.append("replace")
                real_replace(source, destination)

            with (
                mock.patch.object(PUSH.os, "fsync", side_effect=fsync),
                mock.patch.object(PUSH.os, "replace", side_effect=replace),
            ):
                PUSH.write_receipt(
                    path,
                    source_sha="c" * 40,
                    pre_write_etag='"pre"',
                    pre_policy_sha256="a" * 64,
                    local_sha256="b" * 64,
                    post_write_etag=None,
                    post_policy_sha256=None,
                    write_attempted=True,
                    outcome="write_attempt_pending_reconciliation",
                    changes=[],
                )

            self.assertEqual(events, ["fsync", "replace", "fsync"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_failed_pre_replace_fsync_preserves_prior_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            prior = '{"outcome":"write_attempt_pending_reconciliation"}\n'
            path.write_text(prior, encoding="utf-8")
            with mock.patch.object(
                PUSH.os,
                "fsync",
                side_effect=OSError("simulated file fsync failure"),
            ):
                with self.assertRaisesRegex(OSError, "fsync failure"):
                    PUSH.write_receipt(
                        path,
                        source_sha="c" * 40,
                        pre_write_etag='"pre"',
                        pre_policy_sha256="a" * 64,
                        local_sha256="b" * 64,
                        post_write_etag='"post"',
                        post_policy_sha256="b" * 64,
                        write_attempted=True,
                        outcome="write_accepted_reconciled",
                        changes=[],
                    )
            self.assertEqual(path.read_text(encoding="utf-8"), prior)

    def test_failed_directory_fsync_leaves_complete_replacement_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            calls = 0
            real_fsync = PUSH.os.fsync

            def fail_directory_fsync(descriptor: int) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("simulated directory fsync failure")
                real_fsync(descriptor)

            with mock.patch.object(
                PUSH.os,
                "fsync",
                side_effect=fail_directory_fsync,
            ):
                with self.assertRaisesRegex(OSError, "directory fsync failure"):
                    PUSH.write_receipt(
                        path,
                        source_sha="c" * 40,
                        pre_write_etag='"pre"',
                        pre_policy_sha256="a" * 64,
                        local_sha256="b" * 64,
                        post_write_etag='"post"',
                        post_policy_sha256="b" * 64,
                        write_attempted=True,
                        outcome="write_accepted_reconciled",
                        changes=[],
                    )

            replacement = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                replacement["outcome"],
                "write_accepted_reconciled",
            )

    def test_source_binding_allows_only_exact_head_and_generated_policy(
        self,
    ) -> None:
        expected = "c" * 40
        clean_results = [
            subprocess.CompletedProcess(
                args=["git", "rev-parse", "HEAD"],
                returncode=0,
                stdout=expected + "\n",
                stderr="",
            ),
            subprocess.CompletedProcess(
                args=["git", "status"],
                returncode=0,
                stdout=b"?? generated/policy.json\0",
                stderr=b"",
            ),
        ]
        with mock.patch.object(
            PUSH.subprocess,
            "run",
            side_effect=clean_results,
        ):
            PUSH.verify_source_state(expected)

        dirty_results = [
            clean_results[0],
            subprocess.CompletedProcess(
                args=["git", "status"],
                returncode=0,
                stdout=(
                    b"?? generated/policy.json\0"
                    b" M scripts/push.py\0"
                    b"?? unexpected.dhall\0"
                ),
                stderr=b"",
            ),
        ]
        with mock.patch.object(
            PUSH.subprocess,
            "run",
            side_effect=dirty_results,
        ):
            with self.assertRaisesRegex(RuntimeError, "not clean"):
                PUSH.verify_source_state(expected)

    def test_source_binding_rejects_wrong_head(self) -> None:
        results = [
            subprocess.CompletedProcess(
                args=["git", "rev-parse", "HEAD"],
                returncode=0,
                stdout="d" * 40 + "\n",
                stderr="",
            ),
            subprocess.CompletedProcess(
                args=["git", "status"],
                returncode=0,
                stdout=b"",
                stderr=b"",
            ),
        ]
        with mock.patch.object(PUSH.subprocess, "run", side_effect=results):
            with self.assertRaisesRegex(RuntimeError, "source SHA mismatch"):
                PUSH.verify_source_state("c" * 40)

    def test_plan_oauth_exchange_requests_and_requires_exact_read_scopes(self) -> None:
        expected = PUSH.PLAN_SCOPES
        response = Response(
            {
                "access_token": "read-token",
                "scope": " ".join(reversed(sorted(expected))),
            }
        )
        with (
            mock.patch.object(PUSH.urllib.request, "urlopen", return_value=response)
            as urlopen,
            mock.patch.dict(
                os.environ,
                {"TS_OAUTH_CLIENT_ID": "read-client"},
                clear=False,
            ),
        ):
            token = PUSH.resolve_scoped_bearer("tskey-client-read", expected)

        self.assertEqual(token, "read-token")
        request = urlopen.call_args.args[0]
        form = parse_qs(request.data.decode())
        self.assertEqual(form["client_id"], ["read-client"])
        self.assertEqual(form["scope"], [" ".join(sorted(expected))])

    def test_apply_oauth_exchange_rejects_missing_or_extra_scopes(self) -> None:
        expected = PUSH.APPLY_SCOPES
        cases = {
            "missing": expected - {"policy_file"},
            "extra": expected | {"all:read"},
        }
        for name, returned_scopes in cases.items():
            with self.subTest(name=name):
                response = Response(
                    {
                        "access_token": "wrong-token",
                        "scope": " ".join(sorted(returned_scopes)),
                    }
                )
                with (
                    mock.patch.object(
                        PUSH.urllib.request,
                        "urlopen",
                        return_value=response,
                    ),
                    mock.patch.dict(
                        os.environ,
                        {"TS_OAUTH_CLIENT_ID": "write-client"},
                        clear=False,
                    ),
                ):
                    with self.assertRaisesRegex(RuntimeError, "scope mismatch"):
                        PUSH.resolve_scoped_bearer("tskey-client-write", expected)

    def test_scoped_exchange_rejects_broad_api_key(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "scoped OAuth client"):
            PUSH.resolve_scoped_bearer("tskey-api-broad", PUSH.PLAN_SCOPES)

    def test_fetch_requires_and_retains_etag(self) -> None:
        response = Response({"acls": []}, headers={"ETag": 'W/"opaque"'})
        with mock.patch.object(
            PUSH.urllib.request,
            "urlopen",
            return_value=response,
        ):
            observed = PUSH.fetch_live_acl("token")
        self.assertEqual(observed, PUSH.LiveAcl({"acls": []}, 'W/"opaque"'))

        with mock.patch.object(
            PUSH.urllib.request,
            "urlopen",
            return_value=Response({"acls": []}),
        ):
            with self.assertRaisesRegex(RuntimeError, "no ETag"):
                PUSH.fetch_live_acl("token")

    def test_push_uses_exact_if_match_etag(self) -> None:
        captured = {}

        def open_request(request: object) -> Response:
            captured["request"] = request
            return Response({})

        with mock.patch.object(PUSH.urllib.request, "urlopen", side_effect=open_request):
            result = PUSH.push_acl(
                "token",
                {"acls": []},
                etag='W/"exact-opaque-value"',
            )

        self.assertEqual(result, PUSH.PushAttempt("accepted"))
        request = captured["request"]
        self.assertEqual(request.get_header("If-match"), 'W/"exact-opaque-value"')

    def test_push_classifies_http_412_as_precondition_failure(self) -> None:
        failure = PUSH.urllib.error.HTTPError(
            PUSH.API_BASE + "/acl",
            412,
            "Precondition Failed",
            {},
            None,
        )
        with mock.patch.object(
            PUSH.urllib.request,
            "urlopen",
            side_effect=failure,
        ):
            result = PUSH.push_acl(
                "token",
                {"acls": []},
                etag='"stale"',
            )
        self.assertEqual(
            result,
            PUSH.PushAttempt("precondition_failed", http_status=412),
        )

    def test_push_distinguishes_http_rejection_from_ambiguous_response(
        self,
    ) -> None:
        cases = [
            (
                PUSH.urllib.error.HTTPError(
                    PUSH.API_BASE + "/acl",
                    403,
                    "Forbidden",
                    {},
                    None,
                ),
                PUSH.PushAttempt("rejected", http_status=403),
            ),
            (
                PUSH.urllib.error.HTTPError(
                    PUSH.API_BASE + "/acl",
                    503,
                    "Unavailable",
                    {},
                    None,
                ),
                PUSH.PushAttempt("response_ambiguous", http_status=503),
            ),
            (
                OSError("connection reset after send"),
                PUSH.PushAttempt("response_ambiguous"),
            ),
        ]
        for failure, expected in cases:
            with (
                self.subTest(failure=repr(failure)),
                mock.patch.object(
                    PUSH.urllib.request,
                    "urlopen",
                    side_effect=failure,
                ),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(
                    PUSH.push_acl("token", {"acls": []}, etag='"exact"'),
                    expected,
                )

    def test_reconciled_state_distinguishes_pre_local_and_third_state(
        self,
    ) -> None:
        arguments = {
            "pre_policy_sha256": "a" * 64,
            "local_policy_sha256": "b" * 64,
        }
        self.assertEqual(
            PUSH.reconciled_state(
                **arguments,
                post_policy_sha256="a" * 64,
            ),
            "pre_state",
        )
        self.assertEqual(
            PUSH.reconciled_state(
                **arguments,
                post_policy_sha256="b" * 64,
            ),
            "local_state",
        )
        self.assertEqual(
            PUSH.reconciled_state(
                **arguments,
                post_policy_sha256="c" * 64,
            ),
            "third_state",
        )

    def test_expected_digest_fails_closed(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(PUSH.validate_expected_digest("live", "", "a" * 64))
            self.assertFalse(
                PUSH.validate_expected_digest("live", "b" * 64, "a" * 64)
            )
        self.assertTrue(PUSH.validate_expected_digest("live", "a" * 64, "a" * 64))

    def test_confirm_without_accepted_digests_fails_before_credentials(self) -> None:
        environment = os.environ.copy()
        environment.pop("TAILSCALE_API_KEY", None)
        result = subprocess.run(
            [sys.executable, str(SCRIPTS / "push.py"), "--confirm"],
            capture_output=True,
            check=False,
            env=environment,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("--confirm requires both", result.stderr)
        self.assertNotIn("TAILSCALE_API_KEY environment variable is required", result.stderr)

    def test_confirm_without_receipt_fails_before_credentials(self) -> None:
        environment = os.environ.copy()
        environment.pop("TAILSCALE_API_KEY", None)
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "push.py"),
                "--confirm",
                "--expect-live-sha256",
                "a" * 64,
                "--expect-policy-sha256",
                "b" * 64,
            ],
            capture_output=True,
            check=False,
            env=environment,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("--confirm requires --receipt", result.stderr)
        self.assertNotIn("TAILSCALE_API_KEY environment variable is required", result.stderr)

    def test_wrong_source_binding_fails_before_credentials(self) -> None:
        environment = os.environ.copy()
        environment.pop("TAILSCALE_API_KEY", None)
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "push.py"),
                    "--dry-run",
                    "--source-sha",
                    "c" * 40,
                    "--receipt",
                    str(Path(directory) / "receipt.json"),
                ],
                capture_output=True,
                check=False,
                env=environment,
                text=True,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("source binding failed", result.stderr)
        self.assertNotIn("TAILSCALE_API_KEY environment variable is required", result.stderr)

    def test_stale_live_digest_never_reaches_push(self) -> None:
        live = {"acls": [{"action": "accept", "src": ["old"], "dst": ["dst"]}]}
        local = {"acls": [{"action": "accept", "src": ["new"], "dst": ["dst"]}]}
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            policy.write_text(json.dumps(local), encoding="utf-8")
            receipt = Path(directory) / "receipt.json"
            fetch = mock.Mock(return_value=PUSH.LiveAcl(live, '"before"'))
            push = mock.Mock(return_value=PUSH.PushAttempt("accepted"))
            argv = [
                "push.py",
                "--confirm",
                "--expect-live-sha256",
                "c" * 64,
                "--expect-policy-sha256",
                PUSH.policy_sha256(local),
                "--source-sha",
                "c" * 40,
                "--receipt",
                str(receipt),
            ]
            with (
                mock.patch.object(PUSH, "GENERATED_POLICY", policy),
                mock.patch.object(
                    PUSH,
                    "verify_source_state",
                    return_value=None,
                ),
                mock.patch.object(PUSH, "fetch_live_acl", fetch),
                mock.patch.object(PUSH, "push_acl", push),
                mock.patch.object(
                    PUSH,
                    "resolve_scoped_bearer",
                    return_value="scoped-token",
                ),
                mock.patch.object(sys, "argv", argv),
                mock.patch.dict(
                    os.environ,
                    {"TAILSCALE_API_KEY": "tskey-client-test"},
                    clear=False,
                ),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                result = PUSH.main()
        self.assertEqual(result, 3)
        push.assert_not_called()

    def test_apply_rechecks_zero_diff_after_push(self) -> None:
        live = {"acls": [{"action": "accept", "src": ["old"], "dst": ["dst"]}]}
        local = {"acls": [{"action": "accept", "src": ["new"], "dst": ["dst"]}]}
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            policy.write_text(json.dumps(local), encoding="utf-8")
            receipt = Path(directory) / "receipt.json"
            events = []
            observations = iter(
                [
                    PUSH.LiveAcl(live, '"before"'),
                    PUSH.LiveAcl(local, '"after"'),
                ]
            )

            def fetch_acl(*args: object, **kwargs: object) -> object:
                events.append("fetch")
                return next(observations)

            fetch = mock.Mock(side_effect=fetch_acl)

            def push_acl(*args: object, **kwargs: object) -> object:
                events.append("push")
                return PUSH.PushAttempt("accepted")

            push = mock.Mock(side_effect=push_acl)
            real_write_receipt = PUSH.write_receipt

            def write_receipt(*args: object, **kwargs: object) -> None:
                events.append(f"receipt:{kwargs['outcome']}")
                real_write_receipt(*args, **kwargs)

            receipt_writer = mock.Mock(side_effect=write_receipt)
            argv = [
                "push.py",
                "--confirm",
                "--expect-live-sha256",
                PUSH.policy_sha256(live),
                "--expect-policy-sha256",
                PUSH.policy_sha256(local),
                "--source-sha",
                "d" * 40,
                "--receipt",
                str(receipt),
            ]
            with (
                mock.patch.object(PUSH, "GENERATED_POLICY", policy),
                mock.patch.object(
                    PUSH,
                    "verify_source_state",
                    return_value=None,
                ),
                mock.patch.object(PUSH, "fetch_live_acl", fetch),
                mock.patch.object(PUSH, "push_acl", push),
                mock.patch.object(PUSH, "write_receipt", receipt_writer),
                mock.patch.object(
                    PUSH,
                    "resolve_scoped_bearer",
                    return_value="scoped-token",
                ),
                mock.patch.object(sys, "argv", argv),
                mock.patch.dict(
                    os.environ,
                    {"TAILSCALE_API_KEY": "tskey-client-test"},
                    clear=False,
                ),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                result = PUSH.main()
            recorded = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(result, 0)
        self.assertEqual(fetch.call_count, 2)
        push.assert_called_once_with("scoped-token", local, etag='"before"')
        self.assertEqual(recorded["source_sha"], "d" * 40)
        self.assertEqual(recorded["pre_write_etag"], '"before"')
        self.assertEqual(recorded["post_write_etag"], '"after"')
        self.assertEqual(recorded["pre_policy_sha256"], PUSH.policy_sha256(live))
        self.assertEqual(recorded["post_policy_sha256"], PUSH.policy_sha256(local))
        self.assertTrue(recorded["write_attempted"])
        self.assertEqual(recorded["outcome"], "write_accepted_reconciled")
        self.assertEqual(
            events,
            [
                "fetch",
                "receipt:write_attempt_pending_reconciliation",
                "push",
                "fetch",
                "receipt:write_accepted_reconciled",
            ],
        )

    def test_ambiguous_local_state_reconciles_before_terminal_receipt(
        self,
    ) -> None:
        live = {"acls": [{"action": "accept", "src": ["old"], "dst": ["dst"]}]}
        local = {"acls": [{"action": "accept", "src": ["new"], "dst": ["dst"]}]}
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            policy.write_text(json.dumps(local), encoding="utf-8")
            receipt = Path(directory) / "receipt.json"
            events = []
            observations = iter(
                [
                    PUSH.LiveAcl(live, '"before"'),
                    PUSH.LiveAcl(local, '"after-ambiguous"'),
                ]
            )

            def fetch_acl(*args: object, **kwargs: object) -> object:
                events.append("fetch")
                return next(observations)

            def push_acl(*args: object, **kwargs: object) -> object:
                events.append("push")
                return PUSH.PushAttempt("response_ambiguous")

            real_write_receipt = PUSH.write_receipt

            def write_receipt(*args: object, **kwargs: object) -> None:
                events.append(f"receipt:{kwargs['outcome']}")
                real_write_receipt(*args, **kwargs)

            argv = [
                "push.py",
                "--confirm",
                "--expect-live-sha256",
                PUSH.policy_sha256(live),
                "--expect-policy-sha256",
                PUSH.policy_sha256(local),
                "--source-sha",
                "e" * 40,
                "--receipt",
                str(receipt),
            ]
            with (
                mock.patch.object(PUSH, "GENERATED_POLICY", policy),
                mock.patch.object(
                    PUSH,
                    "verify_source_state",
                    return_value=None,
                ),
                mock.patch.object(PUSH, "fetch_live_acl", side_effect=fetch_acl),
                mock.patch.object(PUSH, "push_acl", side_effect=push_acl),
                mock.patch.object(
                    PUSH,
                    "write_receipt",
                    side_effect=write_receipt,
                ),
                mock.patch.object(
                    PUSH,
                    "resolve_scoped_bearer",
                    return_value="scoped-token",
                ),
                mock.patch.object(sys, "argv", argv),
                mock.patch.dict(
                    os.environ,
                    {"TAILSCALE_API_KEY": "tskey-client-test"},
                    clear=False,
                ),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                result = PUSH.main()
            recorded = json.loads(receipt.read_text(encoding="utf-8"))

        self.assertEqual(result, 1)
        self.assertEqual(
            recorded["outcome"],
            "write_response_ambiguous_reconciled_local_state",
        )
        self.assertEqual(
            events,
            [
                "fetch",
                "receipt:write_attempt_pending_reconciliation",
                "push",
                "fetch",
                "receipt:write_response_ambiguous_reconciled_local_state",
            ],
        )

    def test_concurrent_change_returns_412_and_records_confirmed_no_write(
        self,
    ) -> None:
        live = {"acls": [{"action": "accept", "src": ["old"], "dst": ["dst"]}]}
        local = {"acls": [{"action": "accept", "src": ["new"], "dst": ["dst"]}]}
        concurrent = {
            "acls": [{"action": "accept", "src": ["other"], "dst": ["dst"]}]
        }
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            policy.write_text(json.dumps(local), encoding="utf-8")
            receipt = Path(directory) / "receipt.json"
            fetch = mock.Mock(
                side_effect=[
                    PUSH.LiveAcl(live, '"accepted-plan-etag"'),
                    PUSH.LiveAcl(concurrent, '"concurrent-etag"'),
                ]
            )
            push = mock.Mock(
                return_value=PUSH.PushAttempt("precondition_failed")
            )
            argv = [
                "push.py",
                "--confirm",
                "--expect-live-sha256",
                PUSH.policy_sha256(live),
                "--expect-policy-sha256",
                PUSH.policy_sha256(local),
                "--source-sha",
                "e" * 40,
                "--receipt",
                str(receipt),
            ]
            with (
                mock.patch.object(PUSH, "GENERATED_POLICY", policy),
                mock.patch.object(
                    PUSH,
                    "verify_source_state",
                    return_value=None,
                ),
                mock.patch.object(PUSH, "fetch_live_acl", fetch),
                mock.patch.object(PUSH, "push_acl", push),
                mock.patch.object(
                    PUSH,
                    "resolve_scoped_bearer",
                    return_value="scoped-token",
                ),
                mock.patch.object(sys, "argv", argv),
                mock.patch.dict(
                    os.environ,
                    {"TAILSCALE_API_KEY": "tskey-client-test"},
                    clear=False,
                ),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                result = PUSH.main()
            recorded = json.loads(receipt.read_text(encoding="utf-8"))

        self.assertEqual(result, 4)
        self.assertEqual(fetch.call_count, 2)
        push.assert_called_once_with(
            "scoped-token",
            local,
            etag='"accepted-plan-etag"',
        )
        self.assertEqual(
            recorded["outcome"],
            "precondition_failed_confirmed_no_write",
        )
        self.assertTrue(recorded["write_attempted"])
        self.assertEqual(recorded["pre_write_etag"], '"accepted-plan-etag"')
        self.assertEqual(recorded["post_write_etag"], '"concurrent-etag"')
        self.assertEqual(
            recorded["post_policy_sha256"],
            PUSH.policy_sha256(concurrent),
        )

    def test_ambiguous_write_is_always_reconciled_and_classified(self) -> None:
        live = {"acls": [{"action": "accept", "src": ["old"], "dst": ["dst"]}]}
        local = {"acls": [{"action": "accept", "src": ["new"], "dst": ["dst"]}]}
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            policy.write_text(json.dumps(local), encoding="utf-8")
            receipt = Path(directory) / "receipt.json"
            fetch = mock.Mock(
                side_effect=[
                    PUSH.LiveAcl(live, '"before"'),
                    PUSH.LiveAcl(live, '"after-failure"'),
                ]
            )
            push = mock.Mock(
                return_value=PUSH.PushAttempt("response_ambiguous")
            )
            argv = [
                "push.py",
                "--confirm",
                "--expect-live-sha256",
                PUSH.policy_sha256(live),
                "--expect-policy-sha256",
                PUSH.policy_sha256(local),
                "--source-sha",
                "f" * 40,
                "--receipt",
                str(receipt),
            ]
            with (
                mock.patch.object(PUSH, "GENERATED_POLICY", policy),
                mock.patch.object(
                    PUSH,
                    "verify_source_state",
                    return_value=None,
                ),
                mock.patch.object(PUSH, "fetch_live_acl", fetch),
                mock.patch.object(PUSH, "push_acl", push),
                mock.patch.object(
                    PUSH,
                    "resolve_scoped_bearer",
                    return_value="scoped-token",
                ),
                mock.patch.object(sys, "argv", argv),
                mock.patch.dict(
                    os.environ,
                    {"TAILSCALE_API_KEY": "tskey-client-test"},
                    clear=False,
                ),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                result = PUSH.main()
            recorded = json.loads(receipt.read_text(encoding="utf-8"))

        self.assertEqual(result, 1)
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(
            recorded["outcome"],
            "write_response_ambiguous_reconciled_pre_state",
        )
        self.assertTrue(recorded["write_attempted"])
        self.assertEqual(recorded["post_write_etag"], '"after-failure"')


if __name__ == "__main__":
    unittest.main()
