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
      , { mapKey = C.group.qa_engineers, mapValue = [] : List Text }
      ]

let tagOwners
    : List T.TagOwner
    = [ { mapKey = C.tag.dollhouse
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.services
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.k8s
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.k8s_operator
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tsidp
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.dev
        , mapValue = [ C.autogroup.admin, C.group.developers ]
        }
      , { mapKey = C.tag.staging
        , mapValue = [ C.autogroup.admin, C.group.developers ]
        }
      , { mapKey = C.tag.qa
        , mapValue =
          [ C.autogroup.admin, C.group.developers, C.group.qa_engineers ]
        }
      , { mapKey = C.tag.exit_node
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.switch
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.subnet_router
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tinyland_lab_common
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tinyland_lab_sunshine
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tinyland_lab_moonlight
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tinyland_lab_crush
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tinyland_lab_runner
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tinyland_lab_dev
        , mapValue = [ C.autogroup.admin, C.group.developers ]
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
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.setec
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.ci_agent
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.kvm_proxy
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
