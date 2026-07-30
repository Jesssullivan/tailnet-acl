-- Core fragment: groups, tag owners, and base user access rules.
-- This is the foundation that all other fragments build on.
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
      , { mapKey = C.tag.rke2_egress
        , mapValue =
          [ C.tag.k8s_operator
          , C.autogroup.admin
          , C.group.dollhouse_admins
          ]
        }
      , { mapKey = C.tag.mcp_proxy
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tsidp
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
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
      ]

let acls
    : List T.ACLRule
    = [ { action = "accept"
        , src = [ C.group.dollhouse_users, C.group.dollhouse_admins ]
        , dst = [ "${C.tag.dev}:*", "${C.tag.dollhouse}:*" ]
        }
      ]

in  { groups, tagOwners, acls }
