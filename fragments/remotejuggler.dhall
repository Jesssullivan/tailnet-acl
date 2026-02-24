-- RemoteJuggler fragment: rj-gateway, setec, ci-agent access.
-- Split into two groups to match live ACL ordering.

let T = ../types/ACL.dhall

let C = ../constants.dhall

-- rj-gateway to setec (appears after internet access)
let aclsEarly
    : List T.ACLRule
    = [ { action = "accept"
        , src = [ C.tag.rj_gateway ]
        , dst = [ "${C.tag.setec}:*" ]
        }
      ]

-- admins to rj-gateway/setec (appears after aperture)
let aclsLate
    : List T.ACLRule
    = [ { action = "accept"
        , src = [ C.group.dollhouse_admins ]
        , dst = [ "${C.tag.rj_gateway}:*", "${C.tag.setec}:*" ]
        }
      ]

in  { aclsEarly, aclsLate }
