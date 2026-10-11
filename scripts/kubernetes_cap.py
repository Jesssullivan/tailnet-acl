"""Contract for tailscale.com/cap/kubernetes values (R-C557..R-C562, TIN-6192).

honey's Tailscale operator API server proxy (tailscale v1.102.4,
k8s-operator/api-proxy/proxy.go, addImpersonationHeaders) strips the caller's
Authorization and Impersonate-* headers, then decodes the caller's
tailscale.com/cap/kubernetes rules, falling back to the legacy name
https://tailscale.com/cap/kubernetes when the current name has none. If that
decode fails it only logs the error and forwards the request with no
impersonation headers, i.e. as the operator's own ServiceAccount. Go's JSON
decoder also ignores unknown keys, so a misspelled key decodes to an empty
rule, and a tagged caller with no cap groups is then impersonated with its
tags as groups.

Upstream's rule shape (kube/kubetypes/grants.go at v1.102.4):

    KubernetesCapRule {
        Impersonate     *ImpersonateRule `json:"impersonate,omitempty"`
        Recorders       []string         `json:"recorder,omitempty"`
        RecorderAddrs   []netip.AddrPort `json:"recorderAddrs,omitempty"`
        EnforceRecorder bool             `json:"enforceRecorder,omitempty"`
        EnableEvents    bool             `json:"enableEvents,omitempty"`
    }
    ImpersonateRule { Groups []string `json:"groups,omitempty"` }

This repository admits a strict subset of that shape, so every admitted value
decodes upstream with a non-empty group list:

* only the current name; the legacy https:// name, and any other spelling of
  the cap, never appears in the policy;
* the value is a non-empty list of objects whose only key is "impersonate";
* "impersonate" is an object whose only key is "groups";
* "groups" is a non-empty list of distinct, non-empty strings, none of them a
  reserved Kubernetes "system:" group (system:masters above all).

Session-recording fields (recorder, enforceRecorder, enableEvents) are valid
upstream but unused here; adding one needs its own review and a change to this
contract. recorderAddrs is populated by control and never belongs in policy.
"""

CAP = "tailscale.com/cap/kubernetes"
LEGACY_CAP = "https://" + CAP
RESERVED_GROUP_PREFIX = "system:"


def _app_maps(policy):
    """Yield (location, app map) for every grant and nodeAttr that carries one."""
    for surface in ("grants", "nodeAttrs"):
        rows = policy.get(surface) if isinstance(policy, dict) else None
        if not isinstance(rows, list):
            continue
        for index, row in enumerate(rows):
            if isinstance(row, dict) and "app" in row:
                yield f"{surface}[{index}]", row["app"]


def _strings(value):
    """Every dict key and string anywhere in value."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)
    elif isinstance(value, str):
        yield value


def _value_violations(where, value):
    if not isinstance(value, list) or not value:
        return [f"{where}: value must be a non-empty list of rules"]
    problems = []
    for position, rule in enumerate(value):
        at = f"{where}[{position}]"
        if not isinstance(rule, dict) or set(rule) != {"impersonate"}:
            problems.append(f"{at}: a rule must be an object whose only key is 'impersonate'")
            continue
        impersonate = rule["impersonate"]
        if not isinstance(impersonate, dict) or set(impersonate) != {"groups"}:
            problems.append(f"{at}.impersonate: must be an object whose only key is 'groups'")
            continue
        groups = impersonate["groups"]
        if not isinstance(groups, list) or not groups:
            problems.append(f"{at}.impersonate.groups: must be a non-empty list of strings")
            continue
        seen = set()
        for slot, group in enumerate(groups):
            gat = f"{at}.impersonate.groups[{slot}]"
            if not isinstance(group, str) or not group or group != group.strip():
                problems.append(f"{gat}: must be a non-empty string without surrounding whitespace")
            elif group.lower().startswith(RESERVED_GROUP_PREFIX):
                problems.append(f"{gat}: reserved Kubernetes system: group")
            elif group in seen:
                problems.append(f"{gat}: duplicate group")
            else:
                seen.add(group)
    return problems


def violations(policy):
    """Return a list of human-readable problems; empty means the policy complies."""
    problems = []
    # The legacy name is forbidden anywhere in the policy, not only as an app key.
    if any(LEGACY_CAP in text.lower() for text in _strings(policy)):
        problems.append(f"policy: the legacy cap name {LEGACY_CAP} is forbidden; use {CAP}")
    for where, app in _app_maps(policy):
        if not isinstance(app, dict):
            problems.append(f"{where}.app: must be an object")
            continue
        for name, value in app.items():
            if name == CAP:
                problems.extend(_value_violations(f"{where}.app[{CAP!r}]", value))
            elif "cap/kubernetes" in name.lower():
                problems.append(f"{where}.app: only the cap name {CAP} is allowed, not {name!r}")
    return problems


def require_compliant(policy):
    """Refuse a candidate with a fixed, value-free message (CD output is public)."""
    from policy_source import PolicyError

    if violations(policy):
        raise PolicyError("candidate policy carries a forbidden or malformed kubernetes capability")
