# RKE2 egress authority

`tag:rke2-egress` is the dedicated data-plane identity for the Tailscale
Kubernetes operator's RKE2 control-plane egress ProxyGroup. It must not be
replaced with `tag:k8s`, `tag:k8s-operator`, or another broadly authorized tag.

The authority is intentionally narrow:

- `tag:k8s-operator` may assign `tag:rke2-egress`; administrators retain
  break-glass ownership.
- A device carrying `tag:rke2-egress` may reach only the `tinyland-honey` host
  alias.
- The only permitted transports are TCP 6443 (Kubernetes API) and TCP 9345
  (RKE2 supervisor).
- The tag has no legacy ACL rule, wildcard destination, wildcard port, subnet,
  SSH, application capability, or tag-management authority.
- No additional direct grant or legacy ACL may target Honey's 6443/9345
  endpoints through the `tinyland-honey` alias, its current IP, a containing
  CIDR, or a wildcard. The source-literal census and compiled-policy guard
  cover all policy fragments, not only rules mentioning `tag:rke2-egress`.

## Existing selector overlap and proof boundary

This contract narrows the new ProxyGroup identity. It does **not** prove
Honey-wide exclusivity or remove authority that reaches the same device through
mutable tag membership.

The 2026-07-30Z read-only inventory found Honey carrying `tag:dollhouse`,
`tag:subnet-router`, and `tag:switch`. Existing rules for those selectors
include broad paths that can overlap Honey's 6443/9345 endpoints. Those tags
and rules predate this source slice; no live tag or policy migration is
authorized here.

Before claiming that `tag:rke2-egress` is the sole Honey control-plane path,
run a separately attended live preflight that:

1. inventories Honey's current tags and addresses;
2. resolves every grant and legacy ACL destination selector, port wildcard,
   and port range against that membership;
3. records every source that can reach 6443 or 9345; and
4. either accepts that explicit overlap or lands a separately reviewed tag and
   policy migration.

The source-only guards intentionally cover direct alias/IP/CIDR/wildcard
recurrence. They cannot prove facts about mutable live device-tag membership.

This policy is a prerequisite for the TIN-620 Blahaj ProxyGroup source. Apply
and verify the reviewed tailnet policy before creating ProxyGroup devices,
because a ProxyGroup's device tags cannot be changed in place. The Blahaj
resource must request exactly `tag:rke2-egress`.

This source contract does not authorize an ACL push, ProxyGroup creation,
DNSConfig or CoreDNS rollout, cluster mutation, or continuity/failure proof.
Those remain separately attended operations.

ACL planning and publication must follow the
[ACL publication authority](acl-publication-authority.md) sequence.

The generated-policy tests verify the effective compiled contract. The
source-contract test independently guards the same boundary without requiring
Dhall or Nix:

```console
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.test_rke2_egress_source_contract
```

See the Tailscale operator documentation for
[high-availability ProxyGroups](https://tailscale.com/docs/kubernetes-operator/manage-and-configure/high-availability)
and
[tailnet egress Services](https://tailscale.com/docs/kubernetes-operator/egress/access-tailnet-service).
