-- Network fragment: switches, subnet routers, internet access.
-- Split into two groups to match live ACL ordering.

let T = ../types/ACL.dhall

let C = ../constants.dhall

-- Rules that appear after k8s early block (switch/subnet-router access)
let aclsEarly
    : List T.ACLRule
    = [ { action = "accept"
        , src = [ C.tag.switch, C.tag.subnet_router ]
        , dst =
          [ "${C.tag.dollhouse}:*"
          , "${C.tag.dev}:*"
          , "${C.autogroup.internet}:*"
          ]
        }
      , { action = "accept"
        , src = [ C.group.dollhouse_admins ]
        , dst =
          [ "${C.tag.switch}:*", "${C.tag.subnet_router}:*" ]
        }
      , { action = "accept"
        , src = [ C.group.dollhouse_users ]
        , dst = [ "${C.tag.switch}:80", "${C.tag.switch}:443" ]
        }
      ]

-- Internet access rule (appears after lab block)
let aclsLate
    : List T.ACLRule
    = [ { action = "accept"
        , src = [ C.group.dollhouse_users, C.group.dollhouse_admins ]
        , dst = [ "${C.autogroup.internet}:*" ]
        }
      ]

in  { aclsEarly, aclsLate }
