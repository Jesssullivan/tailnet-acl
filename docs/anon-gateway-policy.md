# Isolated anonymous gateway policy

This source declares one dedicated `tag:anon-gateway` identity, owned only by
`autogroup:admin`, with the `mullvad` node attribute and internet-only ACL access.
It does not enroll a device, select an exit, change AP management, advertise a
subnet/exit node, or establish downstream isolation. Enrollment must assign only
this tag; attaching an existing switch, subnet-router, development or cluster tag
adds that tag's permissions because Tailscale access rules are additive.

The existing user/group rules do not give this tagged identity user permissions.
No universal-source ACL or grant is present in the reviewed baseline. There is no
explicit deny to override a later broad grant: the policy contract checks the
new tag's exact permissions and rejects common universal-source selectors.
Actual IPv4/IPv6/private-network containment remains a CRS/AP namespace firewall
and client-proof requirement. Public application endpoints remain reachable as
internet destinations, including applications operated by the lab.

The operator reported the Mullvad add-on active with zero of five device slots
used on September14EDT. A documented policy GET found no Mullvad node attribute;
that is a policy observation, not independent billing verification. The source
change allocates eligibility to this dedicated tag only. It grants no other node
Mullvad eligibility and does not reuse either BE9300's management identity or
shared legacy WireGuard identity.

Delivery follows `docs/policy-delivery.md`: exact committed source, independent
review, reader validation, current baseline/candidate digest and conditional ETag
write through the owning public repository. Main CD uses the existing production
environment and separate OIDC writer. Do not merge merely to obtain a rendered
artifact: a main push dispatches production CD. Review and approval of this patch
must precede that deployment. Enrollment, licensed European exit selection and
AP02 activation have separate reviewed operations and recovery evidence.
