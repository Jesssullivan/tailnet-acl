-- Lab fragment: Tinyland lab machines (sunshine, moonlight, crush, etc.)

let T = ../types/ACL.dhall

let C = ../constants.dhall

let acls
    : List T.ACLRule
    = [ { action = "accept"
        , src = [ C.tag.tinyland_lab_common, C.tag.tinyland_lab_runner ]
        , dst =
          [ "${C.tag.tinyland_lab_common}:22"
          , "${C.tag.tinyland_lab_runner}:22"
          ]
        }
      , { action = "accept"
        , src =
          [ C.tag.tinyland_lab_moonlight, C.tag.tinyland_lab_sunshine ]
        , dst =
          [ "${C.tag.tinyland_lab_sunshine}:47984-47990"
          , "${C.tag.tinyland_lab_sunshine}:47998-48010"
          ]
        }
      , { action = "accept"
        , src =
          [ C.tag.tinyland_lab_sunshine, C.tag.tinyland_lab_moonlight ]
        , dst =
          [ "${C.tag.tinyland_lab_sunshine}:*"
          , "${C.tag.tinyland_lab_moonlight}:*"
          ]
        }
      , { action = "accept"
        , src = [ C.group.dollhouse_admins ]
        , dst =
          [ "${C.tag.tinyland_lab_common}:*"
          , "${C.tag.tinyland_lab_sunshine}:*"
          , "${C.tag.tinyland_lab_moonlight}:*"
          , "${C.tag.tinyland_lab_crush}:*"
          , "${C.tag.tinyland_lab_runner}:*"
          ]
        }
      , { action = "accept"
        , src = [ C.tag.tinyland_lab_crush ]
        , dst = [ "${C.autogroup.internet}:*" ]
        }
      , { action = "accept"
        , src =
          [ C.tag.tinyland_lab_ci_ephemeral, C.tag.tinyland_lab_deploy ]
        , dst =
          [ "${C.tag.dev}:22", "${C.tag.tinyland_lab_common}:22" ]
        }
      , { action = "accept"
        , src = [ C.tag.tinyland_lab_ci_ephemeral ]
        , dst = [ "${C.tag.dev}:*" ]
        }
      , { action = "accept"
        , src = [ C.tag.tinyland_lab_nix_target ]
        , dst =
          [ "${C.autogroup.internet}:443", "${C.autogroup.internet}:80" ]
        }
      ]

in  T.emptyFragment // { acls }
