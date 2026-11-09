-- models.xoxd.ai edge (Linear TIN-6913, parent TIN-8093). Tailscale is the
-- network gate only. Identity is the bearer or JWT that the switch checks.
--
-- The edge is tailnet device models-xoxd, the per-Service proxy of Service
-- models/models-xoxd on tailscale.com/expose (xoxd-ai/fuzzy
-- models/k8s/overlays/honey/edge.yaml). It carries tag:k8s today, the
-- operator's PROXY_TAGS default, so every rule that admits tag:k8s:443 or
-- tag:k8s:* reaches it. This grant names tag:models-edge instead. It is
-- additive: it changes nothing until the device carries tag:models-edge
-- alone, which needs the Service annotation tailscale.com/tags set to
-- tag:models-edge and a retag of the live device. Once the device leaves
-- tag:k8s, this row is its only inbound rule, because no rule names "*",
-- autogroup:tagged or a tailnet CIDR wider than one address
-- (tests/test_policy_contract.py).
--
-- One row, tcp:443 only. The sources are the named callers:
--   * group:dollhouse-admins: Jess's untagged devices, for the UI through
--     OIDC;
--   * neo: Jess's operator seat and the voice-stt desk. It is a tagged
--     device that no group matches, so it is named by host;
--   * sting: pi, Junie, huskycat T3 and the kimi lane through LiteLLM;
--   * honey: the Cade Hermes on-prem homes, host units as User=cade. Honey
--     is also where the pin drift probe reads the device from its netmap.
-- tcp:53 on the edge forwards to the switch's split-DNS responder. Tailnet
-- split DNS sends xoxd.ai to public resolvers, not to the edge, so no row
-- opens 53. The Cade voice worker and the switch's roll tooling reach the
-- switch inside the cluster, not over the tailnet.
-- Not sources: tag:dev, tag:ci-agent, tag:k8s, tag:dollhouse,
-- tag:k8s-operator, petting-zoo-mini and bumble. Adding a caller is one
-- source entry here and its policy tests.
let C = ../constants.dhall

let G = ../types/Grant.dhall

let grants
    : List G.Grant
    = [ G.net
          [ C.group.dollhouse_admins
          , "tinyland-neo"
          , "tinyland-sting"
          , "tinyland-honey"
          ]
          [ C.tag.models_edge ]
          [ "tcp:443" ]
      ]

in  { grants }
