-- Dev environments fragment: dev, staging, qa access patterns.
-- Split into two groups to match live ACL ordering.

let T = ../types/ACL.dhall

let C = ../constants.dhall

-- Rules that appear early (after core rule, before dollhouse)
let aclsEarly
    : List T.ACLRule
    = [ { action = "accept"
        , src = [ C.tag.dev ]
        , dst =
          [ "${C.tag.dollhouse}:*"
          , "${C.tag.services}:*"
          , "${C.tag.k8s}:*"
          , "${C.tag.tsidp}:*"
          , "${C.autogroup.internet}:*"
          ]
        }
      , { action = "accept"
        , src = [ C.tag.dev ]
        , dst = [ "${C.tag.dev}:*" ]
        }
      ]

-- Rules that appear later (after k8s ports)
let aclsLate
    : List T.ACLRule
    = [ { action = "accept"
        , src = [ C.group.developers ]
        , dst = [ "${C.tag.dev}:*" ]
        }
      , { action = "accept"
        , src = [ C.group.developers, C.group.qa_engineers ]
        , dst = [ "${C.tag.staging}:*" ]
        }
      , { action = "accept"
        , src = [ C.group.developers, C.group.qa_engineers ]
        , dst = [ "${C.tag.qa}:*" ]
        }
      , { action = "accept"
        , src = [ C.group.dollhouse_admins ]
        , dst =
          [ "${C.tag.dev}:*", "${C.tag.staging}:*", "${C.tag.qa}:*" ]
        }
      ]

in  { aclsEarly, aclsLate }
