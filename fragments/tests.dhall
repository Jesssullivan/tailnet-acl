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
-- R-C1011 (TIN-5770 comment 86411716): tag:mx-relay, the public MX alone.
-- It reaches honey on 25 and 465 and the loki-push ingress on 443, and
-- nothing else: no other honey port (22, the k8s 6443/9345/10250, etcd),
-- no port on bumble or sting, no :22 anywhere. Tests take single ports, so
-- the "no other port" half is proved by tests/test_policy_contract.py over
-- every rule. honey's inbound flows to relay-1 (22, 25, 9100, 9154) hold
-- before the retag (dollhouse mesh) and after it (the tag:mx-relay grant).
-- Tests that need the retag first (src relay-1 denied the voters; neo,
-- sting and bumble denied relay-1:25) belong to the post-window PR.
-- The tag:mx-relay denies also cover the wider reach the retag removes:
-- tag:k8s:6443, tag:k8s-operator:443, ai:443 and a 192.168.0.0/16 address.
-- There is no tag:k8s:443 deny: loki-push is a tag:k8s device that R-C1011
-- grants on 443, so named tag:k8s hosts (an MCP proxy, neo) stand in.
-- The operator :22 paths (neo, and an untagged dollhouse-admins user) and
-- the kept exporter-egress scrape (:9100) hold before and after the retag.
--
-- sshTests (R-C1011): tag:mx-relay holds no Tailscale SSH right as any user
-- on the voters, PZM, or any tag:dollhouse, tag:dev or tag:switch device.
-- The relay itself runs OpenSSH, not Tailscale SSH, so no rule names it as
-- a destination either.
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
      , { src = C.tag.mx_relay
        , proto = "tcp"
        , accept =
          [ "tinyland-honey:25"
          , "tinyland-honey:465"
          , "tinyland-loki-push:443"
          ]
        , deny =
          [ "tinyland-honey:22"
          , "tinyland-honey:80"
          , "tinyland-honey:443"
          , "tinyland-honey:587"
          , "tinyland-honey:2379"
          , "tinyland-honey:6443"
          , "tinyland-honey:9100"
          , "tinyland-honey:9345"
          , "tinyland-honey:10250"
          , "tinyland-bumble:22"
          , "tinyland-bumble:25"
          , "tinyland-bumble:443"
          , "tinyland-bumble:465"
          , "tinyland-bumble:6443"
          , "tinyland-bumble:9345"
          , "tinyland-bumble:10250"
          , "tinyland-sting:22"
          , "tinyland-sting:25"
          , "tinyland-sting:443"
          , "tinyland-sting:465"
          , "tinyland-sting:6443"
          , "tinyland-sting:9345"
          , "tinyland-sting:10250"
          , "tinyland-neo:22"
          , "tinyland-petting-zoo-mini:22"
          , "tinyland-loki-push:3100"
          , "tinyland-loki-observability:3100"
          , "${C.tag.dollhouse}:22"
          , "${C.tag.dollhouse}:6443"
          , "${C.tag.k8s}:6443"
          , "${C.tag.k8s_operator}:443"
          , "tinyland-mcp-arxiv:443"
          , "tinyland-neo:443"
          , "ai:443"
          , "192.168.30.105:22"
          ]
        }
      , { src = "tinyland-honey"
        , proto = "tcp"
        , accept =
          [ "tinyland-relay-1:22"
          , "tinyland-relay-1:25"
          , "tinyland-relay-1:9100"
          , "tinyland-relay-1:9154"
          ]
        , deny = [ "tinyland-loki-push:3100" ]
        }
      , { src = "tinyland-neo"
        , proto = "tcp"
        , accept = [ "tinyland-relay-1:22" ]
        , deny = [ "tinyland-loki-observability:22" ]
        }
      , { src = C.user.jess_sulliwood
        , proto = "tcp"
        , accept = [ "tinyland-relay-1:22" ]
        , deny = [ "tinyland-loki-observability:22" ]
        }
      , { src = C.tag.k8s_egress_nodeexporter
        , proto = "tcp"
        , accept = [ "tinyland-relay-1:9100" ]
        , deny =
          [ "tinyland-relay-1:22"
          , "tinyland-relay-1:25"
          , "tinyland-relay-1:9154"
          ]
        }
      ]

let sshTests
    : List T.SSHDenyTest
    = [ { src = C.tag.mx_relay
        , dst =
          [ "tinyland-honey"
          , "tinyland-bumble"
          , "tinyland-sting"
          , "tinyland-petting-zoo-mini"
          , C.tag.dollhouse
          , C.tag.dev
          , C.tag.switch
          ]
        , deny = [ "root", "jess", "jsullivan2", "admin" ]
        }
      ]

in  { tests, sshTests }
