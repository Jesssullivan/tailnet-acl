"""Bounded Tailscale requests; exceptions never contain response or credential text."""

from contextlib import contextmanager
import http.client
import json
import signal
import threading
import urllib.error
import urllib.request

from policy_source import PolicyError, strict_json_loads

API_BASE = "https://api.tailscale.com/api/v2/tailnet/taila4c78d.ts.net"
TIMEOUT_SECONDS = 20
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # urllib's default GET redirect can forward Authorization to another origin.
        raise PolicyError("API redirect refused")


OPENER = urllib.request.build_opener(_NoRedirect())


@contextmanager
def elapsed_deadline(seconds):
    # Signals interrupt blocking/trickling reads, unlike a per-socket idle timeout.
    if threading.current_thread() is not threading.main_thread() or not hasattr(signal, "setitimer"):
        raise PolicyError("elapsed HTTP deadline requires a POSIX main thread")
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise PolicyError("another elapsed deadline is already active")
    previous = signal.getsignal(signal.SIGALRM)
    def expire(_signum, _frame):
        raise PolicyError("API request exceeded elapsed deadline")
    signal.signal(signal.SIGALRM, expire)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def request_bytes(request, allow_error=False, max_response_bytes=None):
    if max_response_bytes is None:
        max_response_bytes = MAX_RESPONSE_BYTES
    if type(max_response_bytes) is not int or not 0 < max_response_bytes <= MAX_RESPONSE_BYTES:
        raise PolicyError("API response limit is invalid")
    try:
        with elapsed_deadline(TIMEOUT_SECONDS), OPENER.open(request, timeout=TIMEOUT_SECONDS) as response:
            chunks, size = [], 0
            while True:
                chunk = response.read(min(65536, max_response_bytes + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > max_response_bytes:
                    raise PolicyError("API response exceeds the size limit")
                chunks.append(chunk)
            body = b"".join(chunks)
            return response.status, body, response.headers.get("ETag", "")
    except urllib.error.HTTPError as exc:
        if allow_error:
            return exc.code, b"", ""
        raise PolicyError(f"API request failed (HTTP {exc.code})") from None
    except (OSError, urllib.error.URLError):
        raise PolicyError("API request failed (transport or timeout)") from None
    except (ValueError, http.client.HTTPException):
        # Invalid header diagnostics can include the Authorization value.
        raise PolicyError("API request failed (invalid request or response)") from None


def parse_object(body):
    try:
        result = strict_json_loads(body)
    except PolicyError:
        raise PolicyError("API response is malformed") from None
    if not isinstance(result, dict):
        raise PolicyError("API response has an invalid shape")
    return result


def fetch_live_acl(bearer):
    request = urllib.request.Request(API_BASE + "/acl", headers={"Authorization": "Bearer " + bearer, "Accept": "application/json"})
    status, body, etag = request_bytes(request)
    if status != 200:
        raise PolicyError(f"ACL read failed (HTTP {status})")
    policy = parse_object(body)
    if not isinstance(policy.get("acls"), list) and not isinstance(policy.get("grants"), list):
        raise PolicyError("ACL response does not contain recognized rules")
    return policy, etag


def strong_etag(value):
    if not value or value.startswith("W/") or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise PolicyError("live policy ETag is missing or invalid")
    if value.startswith('"') != value.endswith('"'):
        raise PolicyError("live policy ETag is missing or invalid")
    unquoted = value[1:-1] if value.startswith('"') else value
    if not unquoted or '"' in unquoted or unquoted == "*":
        raise PolicyError("live policy ETag is missing or invalid")
    return '"' + unquoted + '"'


def push_acl(bearer, policy, etag):
    request = urllib.request.Request(API_BASE + "/acl", data=json.dumps(policy).encode(), method="POST", headers={
        "Authorization": "Bearer " + bearer, "Accept": "application/json",
        "Content-Type": "application/json", "If-Match": strong_etag(etag),
    })
    status, _body, _etag = request_bytes(request)
    if status != 200:
        raise PolicyError(f"ACL update failed (HTTP {status})")
