-- SSH fragment: ALL SSH rules.
-- CRITICAL: These rules control SSH access. Changes here can lock users out.
-- Review carefully before applying.
--
-- icebox (IB-7, Linear TIN-7812): group:icebox-dev gets Tailscale SSH to
-- tag:icebox-dev with accept; group:icebox-prod gets it to tag:icebox-prod
-- with check, so each prod session re-authenticates on Tailscale's default
-- check period. Both admit non-root users only.
let T = ../types/ACL.dhall

let C = ../constants.dhall

let ssh
    : List T.SSHRule
    = [ { action = "accept"
        , src = [ C.group.dollhouse_admins, C.autogroup.admin ]
        , dst = [ C.tag.dollhouse, C.tag.dev ]
        , users = [ "jess", "jsullivan2", "root", C.autogroup.nonroot ]
        }
      , { action = "accept"
        , src = [ C.group.dollhouse_users ]
        , dst = [ C.tag.dollhouse, C.tag.dev ]
        , users = [ "jess", "jsullivan2", C.autogroup.nonroot ]
        }
      , { action = "accept"
        , src = [ C.tag.dev, C.tag.dollhouse ]
        , dst = [ C.tag.dev, C.tag.dollhouse ]
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
          , C.tag.tinyland_lab_nix_target
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
        , users = [ "admin", "root", "jess", "jsullivan2" ]
        }
      , { action = "accept"
        , src = [ C.group.icebox_dev ]
        , dst = [ C.tag.icebox_dev ]
        , users = [ C.autogroup.nonroot ]
        }
      , { action = "check"
        , src = [ C.group.icebox_prod ]
        , dst = [ C.tag.icebox_prod ]
        , users = [ C.autogroup.nonroot ]
        }
      ]

in  T.emptyFragment // { ssh }
