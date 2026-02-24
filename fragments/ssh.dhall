-- SSH fragment: ALL SSH rules.
-- CRITICAL: These rules control SSH access. Changes here can lock users out.
-- Review carefully before applying.
let T = ../types/ACL.dhall

let C = ../constants.dhall

let ssh
    : List T.SSHRule
    = [ { action = "accept"
        , src = [ C.user.jsullivan2_gmail ]
        , dst = [ C.tag.dollhouse, C.tag.dev ]
        , users = [ "jsullivan2", "root", C.autogroup.nonroot ]
        }
      , { action = "accept"
        , src = [ C.group.dollhouse_admins, C.autogroup.admin ]
        , dst = [ C.tag.dollhouse, C.tag.dev ]
        , users = [ "jsullivan2", "root", C.autogroup.nonroot ]
        }
      , { action = "accept"
        , src = [ C.group.dollhouse_users ]
        , dst = [ C.tag.dollhouse, C.tag.dev ]
        , users = [ "jsullivan2", C.autogroup.nonroot ]
        }
      , { action = "accept"
        , src = [ C.tag.dev ]
        , dst = [ C.tag.dev ]
        , users = [ "jess", "jsullivan2", "root", C.autogroup.nonroot ]
        }
      , { action = "accept"
        , src = [ C.tag.dev ]
        , dst = [ C.tag.dollhouse ]
        , users = [ "jess", "jsullivan2", "root", C.autogroup.nonroot ]
        }
      , { action = "accept"
        , src = [ C.tag.dollhouse ]
        , dst = [ C.tag.dollhouse ]
        , users = [ "jess", "jsullivan2", "root", C.autogroup.nonroot ]
        }
      , { action = "accept"
        , src = [ C.tag.dollhouse ]
        , dst = [ C.tag.dev ]
        , users = [ "jess", "jsullivan2", "root", C.autogroup.nonroot ]
        }
      , { action = "accept"
        , src = [ C.group.dollhouse_admins ]
        , dst =
          [ C.tag.tinyland_lab_common
          , C.tag.tinyland_lab_sunshine
          , C.tag.tinyland_lab_moonlight
          , C.tag.tinyland_lab_crush
          , C.tag.tinyland_lab_runner
          ]
        , users = [ "jess", "jsullivan2", "root", C.autogroup.nonroot ]
        }
      , { action = "accept"
        , src = [ C.tag.tinyland_lab_common, C.tag.tinyland_lab_runner ]
        , dst =
          [ C.tag.tinyland_lab_common
          , C.tag.tinyland_lab_sunshine
          , C.tag.tinyland_lab_moonlight
          ]
        , users = [ "jess", "jsullivan2", C.autogroup.nonroot ]
        }
      , { action = "accept"
        , src = [ C.tag.tinyland_lab_ci_ephemeral, C.tag.tinyland_lab_deploy ]
        , dst = [ C.tag.dev, C.tag.tinyland_lab_common ]
        , users = [ "jsullivan2", "jess", C.autogroup.nonroot ]
        }
      , { action = "accept"
        , src = [ C.group.dollhouse_admins, C.tag.dev, C.tag.dollhouse ]
        , dst = [ C.tag.switch ]
        , users = [ "admin" ]
        }
      , { action = "accept"
        , src = [ C.tag.switch ]
        , dst = [ C.tag.dollhouse, C.tag.dev ]
        , users = [ "admin", "root", "jsullivan2" ]
        }
      ]

in  T.emptyFragment // { ssh }
