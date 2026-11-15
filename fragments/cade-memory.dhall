-- Cade memory writer (Linear TIN-7697). Tailscale is the network gate only.
-- Identity is the per-host key that the writer checks itself, so each source
-- host presents its own key and the writer stamps the host from it.
--
-- The writer is tailnet device cade-memory-writer, the proxy of the Tailscale
-- Ingress cade-production/cade-memory-writer (xoxd-ai/blahaj
-- deploy/tenants/cade-production/ingress-cade-memory-writer.yaml). The honey
-- Tailscale operator mints it with tag:cade-memory-writer alone, set by the
-- Ingress annotation tailscale.com/tags. It never carries tag:k8s, so this row
-- is its only inbound rule: no rule names "*", autogroup:tagged or a tailnet
-- CIDR wider than one address (tests/test_policy_contract.py).
--
-- One row, tcp:443 only. The proxy ends TLS on 443 and forwards plain HTTP to
-- Service cade-memory-writer on 8080 inside the cluster. The sources are the
-- four hosts whose spool senders post session segments:
--   * sting, neo, yoga and honey. Each is a tagged device whose tags it shares
--     with other devices (tag:dollhouse, tag:dev, tag:k8s), so each is named
--     by its host alias, as the tag:printstack and tag:softproxy rows do.
-- IPv4 only: the tinyland-* host aliases are IPv4 literals. A packet from a
-- sender's tailnet IPv6 address matches no source here, so a sender must
-- reach the device over IPv4.
-- Not sources: any group, any tag, bumble and petting-zoo-mini. Adding a
-- sender is one source entry here and its policy tests.
let C = ../constants.dhall

let G = ../types/Grant.dhall

let grants
    : List G.Grant
    = [ G.net
          [ "tinyland-sting"
          , "tinyland-neo"
          , "tinyland-yoga"
          , "tinyland-honey"
          ]
          [ C.tag.cade_memory_writer ]
          [ "tcp:443" ]
      ]

in  { grants }
