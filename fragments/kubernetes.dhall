-- Kubernetes fragment: K8s cluster, operator, and tsidp access.
-- Split into two groups to match live ACL ordering.
let T = ../types/ACL.dhall

let C = ../constants.dhall

let aclsEarly
    : List T.ACLRule
    = [ { action = "accept", src = [ C.tag.k8s ], dst = [ "${C.tag.k8s}:*" ] }
      , { action = "accept"
        , src = [ C.tag.k8s_operator ]
        , dst =
          [ "${C.tag.k8s}:*"
          , "${C.tag.dollhouse}:*"
          , "${C.tag.services}:*"
          , "${C.tag.dev}:*"
          , "${C.tag.staging}:*"
          , "${C.tag.qa}:*"
          ]
        }
      ]

let aclsLate
    : List T.ACLRule
    = [ { action = "accept"
        , src = [ C.group.dollhouse_admins, C.tag.dollhouse ]
        , dst =
          [ "${C.tag.k8s}:6443"
          , "${C.tag.k8s}:30443"
          , "${C.tag.k8s}:10250"
          , "${C.tag.k8s}:2379-2380"
          ]
        }
      , { action = "accept"
        , src = [ C.group.dollhouse_admins, C.tag.k8s ]
        , dst = [ "${C.tag.tsidp}:*" ]
        }
      , { action = "accept"
        , src = [ C.group.dollhouse_admins, C.group.dollhouse_users ]
        , dst = [ "${C.tag.k8s_operator}:*" ]
        }
      , { action = "accept"
        , src = [ C.group.dollhouse_admins, C.group.dollhouse_users ]
        , dst = [ "${C.tag.k8s}:*" ]
        }
      , { action = "accept"
        , src =
          [ C.tag.tinyland_lab_common
          , C.tag.dollhouse
          , C.group.dollhouse_admins
          ]
        , dst =
          [ "${C.tag.k8s}:4222"
          , "${C.tag.k8s}:8333"
          , "${C.tag.k8s}:8888"
          , "${C.tag.k8s}:9333"
          ]
        }
      ]

in  { aclsEarly, aclsLate }
