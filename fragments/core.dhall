-- Core fragment: groups, tag owners, and base user access rules.
-- This is the foundation that all other fragments build on.
--
-- group:gftb-qa (operator ruling 2026-10-03, verbatim: "this is the intent; I
-- can add users to the qa tag as needed."): the one group admitted to the
-- greatfallstoolbus.org membership surface. Users go in groups (devices carry
-- tags), so this is a group, not tag:qa. It starts with the operator's own
-- identities; the operator adds QA users here.
--
-- tag:gftb-idp: the GFTB tsidp node (operator rulings 2026-10-03; lab
-- TAILNET_MEMBERSHIP_DETECTION_DESIGN_2026-10-03.md 4.3). New, so no existing
-- device inherits its grants or Funnel (tag:tsidp is held by several
-- devices). Admin-only owner, like tag:gftb-probe, so no tagged device can
-- mint it next to another tag.
--
-- tag:printstack (R-GOLIVE-20261020-c, operator 2026-10-20, Linear TIN-6787,
-- verbatim: "Approve the tag:printstack ACL change"): the honey Tailscale
-- operator mints the printstack-vision and printstack-mcp Ingress proxies and
-- the printstack-mbp13 egress proxy with it (xoxd-ai/printstack
-- deploy/k8s/*, STAGED.md D7). Owned like tag:mcp-proxy, by tag:k8s-operator
-- plus the admins; tag:k8s-operator itself is not broadened.
--
-- tag:mx-relay: the public MX relay-1 alone (R-C1011, TIN-5770 comment
-- 86411716, from the R-C965 exploration). It replaces tag:dollhouse on that
-- one device so the MX leaves the dollhouse mesh (tag:dollhouse:*) and the
-- dollhouse root Tailscale SSH rule. Owned by autogroup:admin and
-- group:dollhouse-admins only: not tag:tag-authority, so no tagged device
-- can mint it. Its only grants live in fragments/grants.dhall.
--
-- tag:softproxy (GO-02 step 1, Linear TIN-7729; xoxd-ai/softproxy rulings
-- SP-1 and SP-25): Softproxy's own userspace tailscaled node on honey,
-- joined with one single-use auth key the operator mints. Owned by
-- autogroup:admin alone, like tag:gftb-idp and tag:infra-idp, so no tagged
-- device can mint it. Its one grant lives in fragments/grants.dhall. The
-- grant's sources are group:dollhouse-admins and neo (Jess 2026-10-30,
-- softproxy seat session, TIN-7729).
--
-- tag:softproxy-edge and tag:softproxy-upstream (Linear TIN-7371; SP-133,
-- TIN-7125 comment cd969795; route design xoxd-ai/blahaj#2455). The honey
-- Tailscale operator mints both for the softproxy.xoxd.ai route. The edge
-- is the softproxy-xoxd LoadBalancer device. The upstream is the egress
-- proxy to the softproxy node. Each is owned like tag:mcp-proxy and
-- tag:printstack, by tag:k8s-operator plus the admins. Neither owns a tag,
-- and tag:k8s-operator itself is not broadened. Their two grants live in
-- fragments/grants.dhall.
--
-- icebox (Linear TIN-7812, Jess's rulings IB-1 and IB-3 to IB-7 in comments
-- b0d7c34e and ba40e1a6; folds Jesssullivan/tailnet-acl#65, TIN-7811;
-- xoxd-ai/icebox is owned by the PZM icebox seat under
-- R-ICEBOX-20261030-a; IB-10 for tag:icebox-member). Four groups and five
-- tags:
--   * group:icebox-dev holds the developers. group:icebox-prod holds every
--     dev member (IB-1). Tailscale groups cannot nest, so both lists come
--     from one Dhall list. The contract test pins dev as a subset of prod.
--   * group:icebox-dispatchers and group:icebox-keyholders are the
--     dispatcher console roles from #65. Keyholders add members here.
--   * tag:icebox-dev marks bench devices and tag:icebox-prod deployed
--     devices. They replace #65's tag:icebox. tag:icebox-console is the
--     console and ingest node, and tag:icebox-prober is the device prober.
--   * tag:icebox-member marks an icebox member's own device (IB-10,
--     "Tag-based access instead"). It reaches what group:icebox-prod
--     reaches, and every port on tag:icebox-dev.
--     autogroup:admin alone owns each tag (Q5), so no tagged device can
--     mint one.
-- Every group starts with Jess's two identities. Under IB-10 an invitee
-- joins by tagging a device tag:icebox-member, so no personal address
-- enters this public file. The icebox rows live in fragments/grants.dhall and
-- fragments/ssh.dhall.
let T = ../types/ACL.dhall

let C = ../constants.dhall

let iceboxDevMembers = [ C.user.jsullivan2_gmail, C.user.jess_sulliwood ]

let groups
    : List T.Group
    = [ { mapKey = C.group.dollhouse_users
        , mapValue = [ C.user.jsullivan2_gmail, C.user.jess_sulliwood ]
        }
      , { mapKey = C.group.dollhouse_admins
        , mapValue = [ C.user.jsullivan2_gmail, C.user.jess_sulliwood ]
        }
      , { mapKey = C.group.developers
        , mapValue = [ C.user.jsullivan2_gmail, C.user.jess_sulliwood ]
        }
      , { mapKey = C.group.gftb_qa
        , mapValue = [ C.user.jsullivan2_gmail, C.user.jess_sulliwood ]
        }
      , { mapKey = C.group.icebox_dev, mapValue = iceboxDevMembers }
      , { mapKey = C.group.icebox_prod, mapValue = iceboxDevMembers }
      , { mapKey = C.group.icebox_dispatchers
        , mapValue = [ C.user.jsullivan2_gmail, C.user.jess_sulliwood ]
        }
      , { mapKey = C.group.icebox_keyholders
        , mapValue = [ C.user.jsullivan2_gmail, C.user.jess_sulliwood ]
        }
      ]

let tagOwners
    : List T.TagOwner
    = [ { mapKey = C.tag.dollhouse
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.services
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.interim_build
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.honey_relay
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.mx_relay
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.gf_reapi_cell_egress
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.gf_reapi_linux_worker
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.gf_reapi_rocm_worker
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.k8s
        , mapValue =
          [ C.tag.tag_authority
          , C.tag.k8s_operator
          , C.autogroup.admin
          , C.group.dollhouse_admins
          ]
        }
      , { mapKey = C.tag.k8s_operator
        , mapValue =
          [ C.tag.tag_authority
          , C.tag.k8s_operator
          , C.autogroup.admin
          , C.group.dollhouse_admins
          ]
        }
      , { mapKey = C.tag.mcp_proxy
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.k8s_egress_nodeexporter
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tsidp
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.gftb_probe, mapValue = [ C.autogroup.admin ] }
      , { mapKey = C.tag.dev
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.developers ]
        }
      , { mapKey = C.tag.staging
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.developers ]
        }
      , { mapKey = C.tag.qa
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.developers ]
        }
      , { mapKey = C.tag.anon_gateway, mapValue = [ C.autogroup.admin ] }
      , { mapKey = C.tag.exit_node
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.switch
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.subnet_router
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tinyland_lab_common
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tinyland_lab_sunshine
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tinyland_lab_moonlight
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tinyland_lab_crush
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tinyland_lab_runner
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tinyland_lab_deploy
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tinyland_lab_ci_ephemeral
        , mapValue = [ C.tag.tinyland_lab_deploy, C.autogroup.admin ]
        }
      , { mapKey = C.tag.tinyland_lab_nix_target
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.ci_agent
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.kvm_proxy
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tag_authority
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.gftb_idp, mapValue = [ C.autogroup.admin ] }
      , { mapKey = C.tag.infra_idp, mapValue = [ C.autogroup.admin ] }
      , { mapKey = C.tag.tofu_state
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.printstack
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.softproxy, mapValue = [ C.autogroup.admin ] }
      , { mapKey = C.tag.softproxy_edge
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.softproxy_upstream
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.icebox_dev, mapValue = [ C.autogroup.admin ] }
      , { mapKey = C.tag.icebox_prod, mapValue = [ C.autogroup.admin ] }
      , { mapKey = C.tag.icebox_prober, mapValue = [ C.autogroup.admin ] }
      , { mapKey = C.tag.icebox_console, mapValue = [ C.autogroup.admin ] }
      , { mapKey = C.tag.icebox_member, mapValue = [ C.autogroup.admin ] }
      ]

let acls
    : List T.ACLRule
    = [ { action = "accept"
        , src = [ C.group.dollhouse_users, C.group.dollhouse_admins ]
        , dst = [ "${C.tag.dev}:*", "${C.tag.dollhouse}:*" ]
        }
      ]

in  { groups, tagOwners, acls }
