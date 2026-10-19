-- Policy `tests`: Tailscale runs them on every validate and every write and
-- rejects the policy if one fails.
--
-- A test destination that names a tag resolves to every device carrying it.
-- tag:k8s-operator and tag:k8s share devices with tag:dev, which
-- tag:tinyland-lab-ci-ephemeral already reaches on every port, so the
-- denials name the three RKE2 server hosts (none carries tag:dev or
-- tag:k8s-operator). The port set and the impersonation cap of the CI grant
-- are pinned by tests/test_policy_contract.py.
--
-- R-C557/R-C558 (TIN-6192 comment 94eb75c0).
--
-- TIN-6746 P4: the public MX relay-1 reaches the write-only loki-push ingress
-- on 443 and never Loki's raw 3100 (read and write) on either proxy.
let T = ../types/ACL.dhall

let C = ../constants.dhall

let tests
    : List T.ACLTest
    = [ { src = C.tag.tinyland_lab_ci_ephemeral
        , proto = "tcp"
        , accept = [ "${C.tag.k8s_operator}:443", "${C.tag.dev}:22" ]
        , deny =
          [ "tinyland-honey:6443"
          , "tinyland-honey:443"
          , "tinyland-bumble:6443"
          , "tinyland-sting:6443"
          ]
        }
      , { src = C.tag.tinyland_lab_deploy
        , proto = "tcp"
        , accept = [ "${C.tag.dev}:22" ]
        , deny = [ "${C.tag.k8s_operator}:443", "tinyland-honey:6443" ]
        }
      , { src = "tinyland-relay-1"
        , proto = "tcp"
        , accept = [ "tinyland-loki-push:443" ]
        , deny =
          [ "tinyland-loki-push:3100", "tinyland-loki-observability:3100" ]
        }
      ]

in  { tests }
