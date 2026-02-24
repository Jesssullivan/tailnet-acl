-- Dollhouse fragment: home infrastructure rules.
-- Covers tag:dollhouse and tag:services access patterns.
let T = ../types/ACL.dhall

let C = ../constants.dhall

let acls
    : List T.ACLRule
    = [ { action = "accept"
        , src = [ C.group.dollhouse_admins ]
        , dst = [ "${C.tag.dollhouse}:*" ]
        }
      , { action = "accept"
        , src = [ C.group.dollhouse_users ]
        , dst =
          [ "${C.tag.dollhouse}:8100"
          , "${C.tag.dollhouse}:6631"
          , "${C.tag.dollhouse}:8080"
          , "${C.tag.dollhouse}:80"
          , "${C.tag.dollhouse}:443"
          , "${C.tag.dollhouse}:3000"
          , "${C.tag.dollhouse}:40000"
          ]
        }
      , { action = "accept"
        , src = [ C.user.jsullivan2_gmail ]
        , dst = [ "${C.tag.dollhouse}:22" ]
        }
      , { action = "accept"
        , src = [ C.tag.dollhouse ]
        , dst = [ "${C.tag.dollhouse}:*" ]
        }
      , { action = "accept"
        , src = [ C.tag.services ]
        , dst = [ "${C.tag.services}:*" ]
        }
      ]

in  T.emptyFragment // { acls }
