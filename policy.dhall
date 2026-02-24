-- Tailscale ACL Policy for tailnet taila4c78d.ts.net (sulliwood.org)
--
-- This file merges all fragments and adds top-level config (autoApprovers, nodeAttrs).
-- Grants are NOT included here; they live in grants.json and are merged by build.py.
--
-- To build: just build
-- To verify: just validate

let T = ./types/ACL.dhall

let C = ./constants.dhall

-- Import all fragments
let core = ./fragments/core.dhall

let dollhouse = ./fragments/dollhouse.dhall

let kubernetes = ./fragments/kubernetes.dhall

let devEnvs = ./fragments/dev-envs.dhall

let lab = ./fragments/lab.dhall

let network = ./fragments/network.dhall

let remotejuggler = ./fragments/remotejuggler.dhall

let aperture = ./fragments/aperture.dhall

let ssh = ./fragments/ssh.dhall

-- ACL rules are ordered to match the live policy exactly.
-- Fragments with interleaved rules export aclsEarly/aclsLate.
let allACLs =
        core.acls                   -- 0: base user access
      # devEnvs.aclsEarly           -- 1-2: tag:dev outbound
      # dollhouse.acls              -- 3-7: dollhouse + services
      # kubernetes.aclsEarly        -- 8-9: k8s self, operator
      # network.aclsEarly           -- 10-12: switch/subnet
      # kubernetes.aclsLate         -- 13-16: k8s ports, tsidp, operator access
      # devEnvs.aclsLate            -- 17-20: dev/staging/qa by role
      # lab.acls                    -- 21-28: lab machines
      # network.aclsLate            -- 29: internet access
      # remotejuggler.aclsEarly     -- 30: rj-gateway->setec
      # aperture.acls               -- 31: AI gateway
      # remotejuggler.aclsLate      -- 32: admins->rj-gateway/setec

let allNodeAttrs
    : List T.NodeAttr
    = [ { target = [ C.tag.dollhouse ], attr = [ "funnel" ] } ]

let autoApprovers
    : T.AutoApprovers
    = { routes =
        [ { mapKey = "10.0.0.0/8"
          , mapValue = [ C.tag.dollhouse, C.tag.k8s ]
          }
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
