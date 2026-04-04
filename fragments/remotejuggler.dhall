-- RemoteJuggler fragment: rj-gateway, setec, ci-agent access.
-- Split into two groups to match live ACL ordering.
let T = ../types/ACL.dhall

let C = ../constants.dhall

let aclsEarly
    : List T.ACLRule
    = [ { action = "accept"
        , src = [ C.tag.rj_gateway ]
        , dst = [ "${C.tag.setec}:*" ]
        }
      , { action = "accept"
        , src = [ C.tag.ci_agent ]
        , dst = [ "${C.tag.dev}:*", "${C.tag.k8s}:*", "${C.tag.rj_gateway}:*" ]
        }
      , { action = "accept"
        , src = [ C.tag.ci_agent ]
        , dst = [ "${C.autogroup.internet}:*" ]
        }
      ]

let aclsLate
    : List T.ACLRule
    = [ { action = "accept"
        , src = [ C.group.dollhouse_admins ]
        , dst = [ "${C.tag.rj_gateway}:*", "${C.tag.setec}:*" ]
        }
      ]

in  { aclsEarly, aclsLate }
