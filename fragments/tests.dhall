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
-- Post-retag ratchet (R-C1011 closeout step 3, R-C1033; retag T0
-- 2026-10-21T05:52:46Z, receipt TIN-5770 8c460876). These tests name the
-- relay by its host alias, so Tailscale evaluates them against the live
-- device and its tag. They pass only while relay-1 carries tag:mx-relay
-- alone. A rollback to tag:dollhouse fails them, and so does any later
-- re-widening of the relay's tag. Each run of "Validate against live ACL"
-- is therefore a control-side readback of the retag:
--   * relay-1 reaches honey:25/465 and not honey's 22, 6443, 9345 or 10250,
--     nor bumble's or sting's 22, 6443 or 10250;
--   * neo, sting and bumble no longer reach relay-1:25 (the tailnet SMTP
--     probe retirement); sting and bumble do not reach relay-1:22 either;
--   * sshTests: relay-1 has no root Tailscale SSH on the three voters.
--
-- sshTests (R-C1011): tag:mx-relay holds no Tailscale SSH right as any user
-- on the voters, PZM, or any tag:dollhouse, tag:dev or tag:switch device.
-- The relay itself runs OpenSSH, not Tailscale SSH, so no rule names it as
-- a destination either.
--
-- tag:softproxy (GO-02 step 1, TIN-7729; SP-1, SP-25). Both of Jess's
-- identities and neo reach tag:softproxy:443 and no other port on it: not
-- 80, 22, 8080 or the loopback backend port 43140. Neo is admitted because
-- Jess works on it (Jess 2026-10-30, softproxy seat session, TIN-7729).
-- Other identities do not reach it on 443 or 80: tag:dev, tag:dollhouse,
-- tag:k8s-operator, tag:mcp-proxy and the agent seat sting. Each of those
-- rows accepts a flow the policy already grants, since a row needs a
-- non-empty accept. The node has no outbound grant, so it has no row of
-- its own. The contract test pins that it is never a source.
--
-- icebox (Linear TIN-7812; folds #65, TIN-7811). Jess, a dev and prod
-- member, reaches every port on tag:icebox-dev, tag:icebox-prod on 22 and
-- 443 but not 80, and the console on 443 but not 22. Neo reaches the
-- console on 443 and both device tags on 22 only. Each device tag reaches
-- only the console on 443: not the other device tag, its own tag,
-- tag:dollhouse:22, honey on 443 or 6443, ai:443 or a 192.168.0.0/16
-- address. The prober reaches both device tags on 22 and 443 only.
-- tag:icebox-member (IB-10) reaches every port on tag:icebox-dev,
-- tag:icebox-prod on 22 and 443 but not 80, and the console on 443 but
-- not 22. It is denied tag:dollhouse:22, honey on 443 or 6443, ai:443 and
-- a 192.168.0.0/16 address.
-- tag:dev and sting reach neither the console nor a device. Jess is also a
-- dollhouse admin, so her rows cannot prove the denials for an
-- icebox-only person. The contract test proves them for a synthetic
-- icebox-only member. Under IB-10 an invitee's device carries
-- tag:icebox-member, and the row for that tag stands in for the invitee.
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
      , { src = C.tag.printstack
        , proto = "tcp"
        , accept = [ "tinyland-mbp-13:443" ]
        , deny =
          [ "tinyland-mbp-13:7125"
          , "tinyland-mbp-13:22"
          , "tinyland-honey:6443"
          ]
        }
      , { src = C.user.jess_sulliwood
        , proto = "tcp"
        , accept = [ "${C.tag.printstack}:443" ]
        , deny = [ "${C.tag.printstack}:22" ]
        }
      , { src = C.user.jess_sulliwood
        , proto = "tcp"
        , accept = [ "${C.tag.softproxy}:443" ]
        , deny =
          [ "${C.tag.softproxy}:80"
          , "${C.tag.softproxy}:22"
          , "${C.tag.softproxy}:8080"
          , "${C.tag.softproxy}:43140"
          ]
        }
      , { src = C.user.jsullivan2_gmail
        , proto = "tcp"
        , accept = [ "${C.tag.softproxy}:443" ]
        , deny = [ "${C.tag.softproxy}:80", "${C.tag.softproxy}:22" ]
        }
      , { src = C.tag.dev
        , proto = "tcp"
        , accept = [ "${C.tag.dev}:22" ]
        , deny = [ "${C.tag.softproxy}:443", "${C.tag.softproxy}:80" ]
        }
      , { src = C.tag.dollhouse
        , proto = "tcp"
        , accept = [ "${C.tag.dollhouse}:22" ]
        , deny = [ "${C.tag.softproxy}:443", "${C.tag.softproxy}:80" ]
        }
      , { src = C.tag.k8s_operator
        , proto = "tcp"
        , accept = [ "${C.tag.k8s}:443" ]
        , deny = [ "${C.tag.softproxy}:443", "${C.tag.softproxy}:80" ]
        }
      , { src = C.tag.mcp_proxy
        , proto = "tcp"
        , accept = [ "${C.tag.mcp_proxy}:3100" ]
        , deny = [ "${C.tag.softproxy}:443", "${C.tag.softproxy}:80" ]
        }
      , { src = "tinyland-neo"
        , proto = "tcp"
        , accept = [ "${C.tag.softproxy}:443" ]
        , deny =
          [ "${C.tag.softproxy}:80"
          , "${C.tag.softproxy}:22"
          , "${C.tag.softproxy}:8080"
          , "${C.tag.softproxy}:43140"
          ]
        }
      , { src = "tinyland-sting"
        , proto = "tcp"
        , accept = [ "tinyland-loki-observability:3100" ]
        , deny =
          [ "${C.tag.softproxy}:443"
          , "${C.tag.softproxy}:80"
          , "${C.tag.softproxy}:22"
          ]
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
      , { src = "tinyland-relay-1"
        , proto = "tcp"
        , accept = [ "tinyland-honey:25", "tinyland-honey:465" ]
        , deny =
          [ "tinyland-honey:22"
          , "tinyland-honey:6443"
          , "tinyland-honey:9345"
          , "tinyland-honey:10250"
          , "tinyland-bumble:22"
          , "tinyland-bumble:6443"
          , "tinyland-bumble:10250"
          , "tinyland-sting:22"
          , "tinyland-sting:6443"
          , "tinyland-sting:10250"
          ]
        }
      , { src = "tinyland-neo"
        , proto = "tcp"
        , accept = [ "tinyland-relay-1:22" ]
        , deny = [ "tinyland-relay-1:25" ]
        }
      , { src = "tinyland-sting"
        , proto = "tcp"
        , accept = [ "tinyland-loki-observability:3100" ]
        , deny = [ "tinyland-relay-1:25", "tinyland-relay-1:22" ]
        }
      , { src = "tinyland-bumble"
        , proto = "tcp"
        , accept = [ "tinyland-loki-observability:3100" ]
        , deny = [ "tinyland-relay-1:25", "tinyland-relay-1:22" ]
        }
      , { src = C.user.jess_sulliwood
        , proto = "tcp"
        , accept =
          [ "${C.tag.icebox_console}:443"
          , "${C.tag.icebox_dev}:22"
          , "${C.tag.icebox_dev}:8080"
          , "${C.tag.icebox_prod}:22"
          , "${C.tag.icebox_prod}:443"
          ]
        , deny = [ "${C.tag.icebox_console}:22", "${C.tag.icebox_prod}:80" ]
        }
      , { src = C.user.jsullivan2_gmail
        , proto = "tcp"
        , accept =
          [ "${C.tag.icebox_console}:443"
          , "${C.tag.icebox_dev}:80"
          , "${C.tag.icebox_prod}:443"
          ]
        , deny = [ "${C.tag.icebox_console}:22", "${C.tag.icebox_prod}:80" ]
        }
      , { src = "tinyland-neo"
        , proto = "tcp"
        , accept =
          [ "${C.tag.icebox_console}:443"
          , "${C.tag.icebox_dev}:22"
          , "${C.tag.icebox_dev}:80"
          , "${C.tag.icebox_prod}:22"
          , "${C.tag.icebox_prod}:443"
          ]
        , deny = [ "${C.tag.icebox_console}:22", "${C.tag.icebox_prod}:80" ]
        }
      , { src = C.tag.icebox_dev
        , proto = "tcp"
        , accept = [ "${C.tag.icebox_console}:443" ]
        , deny =
          [ "${C.tag.icebox_console}:22"
          , "${C.tag.icebox_dev}:22"
          , "${C.tag.icebox_prod}:22"
          , "${C.tag.dollhouse}:22"
          , "tinyland-honey:443"
          , "tinyland-honey:6443"
          , "ai:443"
          , "192.168.30.105:22"
          ]
        }
      , { src = C.tag.icebox_prod
        , proto = "tcp"
        , accept = [ "${C.tag.icebox_console}:443" ]
        , deny =
          [ "${C.tag.icebox_console}:22"
          , "${C.tag.icebox_prod}:22"
          , "${C.tag.icebox_dev}:22"
          , "${C.tag.dollhouse}:22"
          , "tinyland-honey:443"
          , "tinyland-honey:6443"
          , "ai:443"
          , "192.168.30.105:22"
          ]
        }
      , { src = C.tag.icebox_prober
        , proto = "tcp"
        , accept = [ "${C.tag.icebox_dev}:22", "${C.tag.icebox_prod}:443" ]
        , deny =
          [ "${C.tag.icebox_dev}:80"
          , "${C.tag.icebox_console}:443"
          , "${C.tag.dollhouse}:22"
          , "tinyland-honey:443"
          , "tinyland-honey:6443"
          , "ai:443"
          , "192.168.30.105:22"
          ]
        }
      , { src = C.tag.icebox_member
        , proto = "tcp"
        , accept =
          [ "${C.tag.icebox_dev}:22"
          , "${C.tag.icebox_dev}:8080"
          , "${C.tag.icebox_prod}:22"
          , "${C.tag.icebox_prod}:443"
          , "${C.tag.icebox_console}:443"
          ]
        , deny =
          [ "${C.tag.icebox_prod}:80"
          , "${C.tag.icebox_console}:22"
          , "${C.tag.dollhouse}:22"
          , "tinyland-honey:443"
          , "tinyland-honey:6443"
          , "ai:443"
          , "192.168.30.105:22"
          ]
        }
      , { src = C.tag.dev
        , proto = "tcp"
        , accept = [ "${C.tag.dev}:22" ]
        , deny =
          [ "${C.tag.icebox_console}:443"
          , "${C.tag.icebox_dev}:22"
          , "${C.tag.icebox_prod}:22"
          ]
        }
      , { src = "tinyland-sting"
        , proto = "tcp"
        , accept = [ "tinyland-loki-observability:3100" ]
        , deny =
          [ "${C.tag.icebox_console}:443"
          , "${C.tag.icebox_dev}:22"
          , "${C.tag.icebox_prod}:22"
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
      , { src = "tinyland-relay-1"
        , dst = [ "tinyland-honey", "tinyland-bumble", "tinyland-sting" ]
        , deny = [ "root" ]
        }
      ]

in  { tests, sshTests }
