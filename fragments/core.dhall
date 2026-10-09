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
let T = ../types/ACL.dhall

let C = ../constants.dhall

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
      , { mapKey = C.tag.rj_gateway
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.setec
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
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
      ]

let acls
    : List T.ACLRule
    = [ { action = "accept"
        , src = [ C.group.dollhouse_users, C.group.dollhouse_admins ]
        , dst = [ "${C.tag.dev}:*", "${C.tag.dollhouse}:*" ]
        }
      ]

in  { groups, tagOwners, acls }
