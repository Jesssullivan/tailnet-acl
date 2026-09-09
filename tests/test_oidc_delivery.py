"""Offline trust, exchange, source isolation and one-item provisioning contracts."""

import base64
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.parse
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import github_oidc
import oidc_identity
import policy_ci
from policy_source import PolicyError

REPO = {"id": 1165961732, "full_name": "Jesssullivan/tailnet-acl", "owner": {"id": 37297218}}
WORKFLOW_SHA, BASE_SHA, HEAD_SHA = "a" * 40, "b" * 40, "c" * 40
CLIENT = "federated-client-fixture"
AUDIENCE = "api.tailscale.com/" + CLIENT
IDENTITIES, DIGEST = oidc_identity.load_manifest()


def environment(role="reader"):
    rules = IDENTITIES[role]["customClaimRules"]
    return {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": rules["repository"],
            "GITHUB_REPOSITORY_ID": rules["repository_id"], "GITHUB_REPOSITORY_OWNER_ID": rules["repository_owner_id"],
            "GITHUB_REF": rules["ref"], "GITHUB_EVENT_NAME": rules["event_name"], "GITHUB_WORKFLOW_REF": rules["workflow_ref"],
            "GITHUB_WORKFLOW_SHA": WORKFLOW_SHA, "GITHUB_SHA": WORKFLOW_SHA,
            "TS_FEDERATED_CLIENT_ID": CLIENT, "TS_FEDERATED_AUDIENCE": AUDIENCE,
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://run-actions-1.actions.githubusercontent.com/idtoken?api-version=2.0",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "fixture-request-token"}


def event(role="reader"):
    result = {"repository": copy.deepcopy(REPO)}
    if role == "reader":
        result.update(action="synchronize", pull_request={
            "base": {"sha": BASE_SHA, "ref": "main", "repo": copy.deepcopy(REPO)},
            "head": {"sha": HEAD_SHA, "repo": copy.deepcopy(REPO)}})
    else:
        result.update(before=BASE_SHA, after=WORKFLOW_SHA, deleted=False, ref="refs/heads/main")
    return result


def jwt(role="reader", changes=None):
    item = IDENTITIES[role]
    claims = dict(item["customClaimRules"], iss=item["issuer"], sub=item["subject"], aud=AUDIENCE, workflow_sha=WORKFLOW_SHA)
    claims.update(changes or {})
    return "fixture." + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=") + ".signature"


class TrustTest(unittest.TestCase):
    def check(self, role="reader", env=None, data=None, checkout=WORKFLOW_SHA):
        with mock.patch.object(github_oidc, "head_revision", return_value=checkout):
            return github_oidc.trusted_context(role, env or environment(role), data or event(role))

    def test_roles_have_exact_distinct_scopes_and_no_wildcard_claims(self):
        self.assertEqual(IDENTITIES["reader"]["scopes"], ["policy_file:read", "devices:posture_attributes:read", "devices:core:read"])
        self.assertEqual(IDENTITIES["writer"]["scopes"], ["policy_file", "devices:posture_attributes", "devices:core:read"])
        for role in ("reader", "writer"):
            self.assertEqual(set(IDENTITIES[role]["customClaimRules"]), {"repository", "repository_id", "repository_owner_id", "ref", "event_name", "workflow_ref"})
            self.assertNotIn("*", json.dumps(IDENTITIES[role]))
            self.assertEqual(IDENTITIES[role]["tags"], [])
            self.assertEqual(IDENTITIES[role]["subject"], "repo:Jesssullivan/tailnet-acl:environment:production")
            self.assertEqual(IDENTITIES[role]["customClaimRules"], {
                "repository": "Jesssullivan/tailnet-acl", "repository_id": "1165961732", "repository_owner_id": "37297218",
                "ref": "refs/heads/main", "event_name": "pull_request_target" if role == "reader" else "push",
                "workflow_ref": "Jesssullivan/tailnet-acl/.github/workflows/" + ("policy-validate.yml" if role == "reader" else "cd.yml") + "@refs/heads/main"})

    def test_same_repo_reader_and_main_writer_select_event_commits(self):
        self.assertEqual(self.check(), (BASE_SHA, HEAD_SHA))
        self.assertEqual(self.check("writer"), (BASE_SHA, WORKFLOW_SHA))

    def test_wrong_identity_context_never_passes(self):
        for key in ("GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_ID", "GITHUB_REPOSITORY_OWNER_ID", "GITHUB_REF", "GITHUB_EVENT_NAME", "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA"):
            with self.subTest(key=key):
                env = environment(); env[key] = "untrusted"
                with self.assertRaises(PolicyError):
                    self.check(env=env)
        with self.assertRaisesRegex(PolicyError, "checkout"):
            self.check(checkout=HEAD_SHA)

    def test_fork_renamed_owner_base_or_head_and_non_main_base_fail(self):
        for section in ("head", "base"):
            for key in ("id", "full_name", "owner"):
                with self.subTest(section=section, key=key):
                    data = event(); data["pull_request"][section]["repo"][key] = {"id": 99} if key == "owner" else "other"
                    with self.assertRaises(PolicyError):
                        self.check(data=data)
        data = event(); data["pull_request"]["base"]["ref"] = "other"
        with self.assertRaises(PolicyError):
            self.check(data=data)

    def test_writer_delete_zero_before_or_wrong_after_fail(self):
        for key, value in (("deleted", True), ("before", "0" * 40), ("after", HEAD_SHA), ("ref", "refs/heads/other")):
            with self.subTest(key=key):
                data = event("writer"); data[key] = value
                with self.assertRaises(PolicyError):
                    self.check("writer", data=data)

    def test_fork_cannot_request_jwt_even_with_legacy_key_present(self):
        data = event(); data["pull_request"]["head"]["repo"]["id"] = 17
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "event.json"; path.write_text(json.dumps(data))
            env = dict(environment(), GITHUB_EVENT_PATH=str(path), TAILSCALE_API_KEY="tskey-api-unused-fixture")
            with mock.patch.object(github_oidc, "head_revision", return_value=WORKFLOW_SHA), mock.patch.object(github_oidc, "request_bytes") as request:
                with self.assertRaises(PolicyError):
                    github_oidc.resolve_oidc("reader", env)
                request.assert_not_called()

    def test_request_endpoint_rejects_credentials_redirect_origins_and_audience_override(self):
        for raw in ("https://evil.invalid/", "http://run.actions.githubusercontent.com/", "https://actions.githubusercontent.com.evil.invalid/", "https://name@run.actions.githubusercontent.com/", "https://run.actions.githubusercontent.com:444/", "https://run.actions.githubusercontent.com/?audience=other", "https://run.actions.githubusercontent.com/#fragment", "https://run.actions.githubusercontent.com/\n"):
            with self.subTest(raw=raw), self.assertRaises(PolicyError):
                github_oidc.token_request_url(raw, AUDIENCE)

    def test_wrong_claims_or_malformed_jwt_fail_before_exchange(self):
        for key in ("iss", "sub", "aud", "repository", "repository_id", "repository_owner_id", "ref", "event_name", "workflow_ref", "workflow_sha"):
            with self.subTest(key=key), self.assertRaises(PolicyError):
                github_oidc.checked_jwt(jwt(changes={key: "other"}), "reader", AUDIENCE, WORKFLOW_SHA)
        for value in (None, "", "a.b.c.d", "a.####.b", "a.W10.b", "a.eyJhIjoxLCJhIjoyfQ.b", "a.b.\n"):
            with self.subTest(value=value), self.assertRaises(PolicyError):
                github_oidc.checked_jwt(value, "reader", AUDIENCE, WORKFLOW_SHA)


class ExchangeTest(unittest.TestCase):
    def exchange(self, responses, env=None):
        with mock.patch.object(github_oidc, "trusted_context", return_value=(BASE_SHA, HEAD_SHA)), mock.patch.object(
            github_oidc, "request_bytes", side_effect=responses
        ) as request:
            result = github_oidc.resolve_oidc("reader", env or environment())
            return result, request.call_args_list

    def test_exchange_is_two_bounded_in_memory_requests_no_environment_mutation(self):
        env = environment(); before = dict(env)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            token, calls = self.exchange([(200, json.dumps({"value": jwt()}).encode(), ""), (200, b'{"access_token":"fixture-api-token"}', "")], env)
        self.assertEqual(token, "fixture-api-token")
        self.assertEqual(env, before)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(len(calls), 2)
        first, second = [call.args[0] for call in calls]
        self.assertEqual(first.get_header("Authorization"), "Bearer fixture-request-token")
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(first.full_url).query)["audience"], [AUDIENCE])
        self.assertEqual(second.full_url, "https://api.tailscale.com/api/v2/oauth/token-exchange")
        self.assertEqual(urllib.parse.parse_qs(second.data.decode()), {"client_id": [CLIENT], "jwt": [jwt()]})
        self.assertIsNone(second.get_header("Authorization"))
        self.assertTrue(all(call.kwargs == {"max_response_bytes": 65536} for call in calls))

    def test_missing_id_audience_or_request_token_never_falls_back(self):
        for key in ("TS_FEDERATED_CLIENT_ID", "TS_FEDERATED_AUDIENCE", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"):
            with self.subTest(key=key):
                env = environment(); env.pop(key); env["TAILSCALE_API_KEY"] = "tskey-api-unused-fixture"
                with mock.patch.object(github_oidc, "trusted_context"), mock.patch.object(github_oidc, "request_bytes") as request:
                    with self.assertRaises(PolicyError):
                        github_oidc.resolve_oidc("reader", env)
                    request.assert_not_called()

    def test_bad_claims_response_or_http_prevents_second_request(self):
        for response in ((401, b"private error", ""), (200, b"{}", ""), (200, b'{"value":false}', ""), (200, json.dumps({"value": jwt("writer")}).encode(), ""), (200, b"x" * 65537, "")):
            with self.subTest(response_length=len(response[1])), mock.patch.object(github_oidc, "trusted_context"), mock.patch.object(github_oidc, "request_bytes", return_value=response) as request:
                with self.assertRaises(PolicyError):
                    github_oidc.resolve_oidc("reader", environment())
                self.assertEqual(request.call_count, 1)

    def test_missing_bad_or_rejected_access_token_fails_sanitized(self):
        for body in (b'{}', b'{"access_token":false}', b'{"access_token":"private\\nvalue"}', b'not-json'):
            with self.subTest(body=body):
                with self.assertRaises(PolicyError) as raised:
                    self.exchange([(200, json.dumps({"value": jwt()}).encode(), ""), (200, body, "")])
                self.assertNotIn("private", str(raised.exception))


class DriverTest(unittest.TestCase):
    def test_context_only_never_fetches_compiles_or_requests_token(self):
        with mock.patch.object(policy_ci, "trusted_context", return_value=(BASE_SHA, HEAD_SHA)), mock.patch.object(policy_ci, "_run") as fetch, mock.patch.object(policy_ci, "compile_revision") as compile_, mock.patch.object(policy_ci, "resolve_oidc") as auth:
            policy_ci.run("reader", context_only=True)
            fetch.assert_not_called(); compile_.assert_not_called(); auth.assert_not_called()

    def test_reader_compiles_objects_before_auth_proves_grammar_and_checks_drift(self):
        order = []
        def compile_(revision):
            order.append("compile"); return {"acls": [] if revision == BASE_SHA else [1]}
        def auth(role):
            order.append("auth"); return "fixture-api-token"
        with mock.patch.object(policy_ci, "trusted_context", return_value=(BASE_SHA, HEAD_SHA)), mock.patch.object(policy_ci, "_run") as fetch, mock.patch.object(policy_ci, "compile_revision", side_effect=compile_), mock.patch.object(policy_ci, "resolve_oidc", side_effect=auth), mock.patch.object(policy_ci, "validate_candidate") as prove, mock.patch.object(policy_ci, "fetch_live_acl", return_value=({"acls": []}, '"etag"')), mock.patch.object(policy_ci, "promote") as promote:
            policy_ci.run("reader")
            prove.assert_called_once_with("fixture-api-token", {"acls": [1]}, prove=True)
            promote.assert_not_called()
        self.assertEqual(order, ["compile", "compile", "auth"])
        self.assertEqual(fetch.call_args.args[0], ["git", "fetch", "--no-tags", "--depth=1", "https://github.com/Jesssullivan/tailnet-acl.git", BASE_SHA, HEAD_SHA])

    def test_bad_compilation_never_receives_a_token(self):
        with mock.patch.object(policy_ci, "trusted_context", return_value=(BASE_SHA, HEAD_SHA)), mock.patch.object(policy_ci, "_run"), mock.patch.object(policy_ci, "compile_revision", side_effect=PolicyError("source failed")), mock.patch.object(policy_ci, "resolve_oidc") as auth:
            with self.assertRaises(PolicyError):
                policy_ci.run("reader")
            auth.assert_not_called()


class IdentityTest(unittest.TestCase):
    def metadata(self, role="reader"):
        return dict(copy.deepcopy(IDENTITIES[role]), id=CLIENT, audience=AUDIENCE, key="never-output-any-key-field")

    def test_create_is_one_post_then_exact_get_and_no_sensitive_return(self):
        reply = (200, json.dumps(self.metadata()).encode(), "")
        with mock.patch.object(oidc_identity, "request_bytes", side_effect=[reply, reply]) as request:
            result = oidc_identity.manage_identity("fixture-admin-bearer", "reader", DIGEST)
        self.assertEqual(result, {"role": "reader", "client_id": CLIENT, "audience": AUDIENCE, "metadata_verified": True})
        first, second = [call.args[0] for call in request.call_args_list]
        self.assertEqual(first.get_method(), "POST")
        self.assertEqual(json.loads(first.data), IDENTITIES["reader"])
        self.assertEqual(second.get_method(), "GET")
        self.assertTrue(second.full_url.endswith("/keys/" + CLIENT))

    def test_readback_can_only_get_one_requested_id(self):
        with mock.patch.object(oidc_identity, "request_bytes", return_value=(200, json.dumps(self.metadata()).encode(), "")) as request:
            oidc_identity.manage_identity("fixture-admin-bearer", "reader", DIGEST, CLIENT)
        self.assertEqual(request.call_count, 1)
        self.assertEqual(request.call_args.args[0].get_method(), "GET")

    def test_created_id_is_reported_before_bad_metadata_or_failed_readback_without_retry(self):
        for failure in ("metadata", "get"):
            with self.subTest(failure=failure):
                value = self.metadata()
                if failure == "metadata":
                    value["scopes"] = ["all"]
                responses = [(201, json.dumps(value).encode(), ""), PolicyError("readback failed")]
                output = io.StringIO()
                with contextlib.redirect_stdout(output), mock.patch.object(oidc_identity, "request_bytes", side_effect=responses) as request:
                    with self.assertRaises(PolicyError):
                        oidc_identity.manage_identity("fixture-admin-bearer", "reader", DIGEST)
                self.assertEqual(json.loads(output.getvalue()), {"role": "reader", "created_id": CLIENT, "metadata_verified": False})
                self.assertEqual(request.call_count, 1 if failure == "metadata" else 2)
                self.assertEqual(sum(call.args[0].get_method() == "POST" for call in request.call_args_list), 1)

    def test_nullable_empty_tags_matches_official_provider_normalization(self):
        data = self.metadata(); data["tags"] = None
        self.assertTrue(oidc_identity.checked_metadata(data, IDENTITIES["reader"], "reader", CLIENT)["metadata_verified"])

    def test_wrong_manifest_role_or_id_cannot_reach_api(self):
        for role, digest, client in (("reader", "0" * 64, None), ("writer-broad", DIGEST, None), ("reader", DIGEST, "../keys")):
            with self.subTest(role=role, client=client), mock.patch.object(oidc_identity, "request_bytes") as request:
                with self.assertRaises(PolicyError):
                    oidc_identity.manage_identity("fixture-admin-bearer", role, digest, client)
                request.assert_not_called()

    def test_metadata_rejects_scope_widening_claim_omission_wrong_audience_or_id(self):
        for key, value in (("scopes", ["all"]), ("scopes", None), ("customClaimRules", {}), ("audience", "other"), ("issuer", "https://evil.invalid"), ("subject", "*"), ("id", "other-client"), ("keyType", "client")):
            with self.subTest(key=key):
                data = self.metadata(); data[key] = value
                with self.assertRaises(PolicyError):
                    oidc_identity.checked_metadata(data, IDENTITIES["reader"], "reader", CLIENT)


if __name__ == "__main__":
    unittest.main()
