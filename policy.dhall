-- Tailscale ACL Policy for tailnet taila4c78d.ts.net (sulliwood.org)
--
-- This file merges all fragments and adds top-level config (autoApprovers, nodeAttrs).
-- Grants are NOT included here; they live in grants.json and are merged by build.py.
--
-- To build: just build
-- To verify: just validate
let T = ./types/ACL.dhall

let C = ./constants.dhall

let core = ./fragments/core.dhall

let dollhouse = ./fragments/dollhouse.dhall

let kubernetes = ./fragments/kubernetes.dhall

let devEnvs = ./fragments/dev-envs.dhall

let lab = ./fragments/lab.dhall

let network = ./fragments/network.dhall

let remotejuggler = ./fragments/remotejuggler.dhall

let aperture = ./fragments/aperture.dhall

let ssh = ./fragments/ssh.dhall

let allACLs =
        core.acls
      # devEnvs.aclsEarly
      # dollhouse.acls
      # kubernetes.aclsEarly
      # network.aclsEarly
      # kubernetes.aclsLate
      # devEnvs.aclsLate
      # lab.acls
      # network.aclsLate
      # remotejuggler.aclsEarly
      # aperture.acls
      # remotejuggler.aclsLate

let allNodeAttrs
    : List T.NodeAttr
    = [ { target = [ C.tag.dollhouse ], attr = [ "funnel" ] } ]

let autoApprovers
    : T.AutoApprovers
    = { routes =
        [ { mapKey = "10.0.0.0/8", mapValue = [ C.tag.dollhouse, C.tag.k8s ] }
        , { mapKey = "192.168.0.0/16"
          , mapValue = [ C.tag.subnet_router, C.tag.dollhouse ]
          }
        ]
      , exitNode = [ C.tag.exit_node ]
      }

in  { groups = core.groups
    , tagOwners = core.tagOwners
    , acls = allACLs
    , ssh = ssh.ssh
    , nodeAttrs = allNodeAttrs
    , autoApprovers
    , hosts = aperture.hosts
    }
