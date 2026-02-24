-- Aperture fragment: AI gateway access and host definitions.
let T = ../types/ACL.dhall

let C = ../constants.dhall

let acls
    : List T.ACLRule
    = [ { action = "accept"
        , src =
          [ C.group.dollhouse_admins
          , C.group.dollhouse_users
          , C.tag.dev
          , C.tag.dollhouse
          , C.tag.rj_gateway
          , C.tag.ci_agent
          , C.tag.k8s_operator
          , C.tag.k8s
          ]
        , dst = [ "ai:*" ]
        }
      ]

let hosts
    : List T.Host
    = [ { mapKey = "ai", mapValue = C.host.ai } ]

in  T.emptyFragment // { acls, hosts }
