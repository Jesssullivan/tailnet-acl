-- Tailscale ACL Policy for tailnet taila4c78d.ts.net (sulliwood.org)
--
-- This file merges all fragments and adds top-level config (autoApprovers, nodeAttrs).
-- Grants are NOT included here; they live in grants.json and are merged by build.py.
--
-- To build: just build
-- To verify: just validate
--
-- Funnel for tag:tsidp (operator rulings 2026-10-03): Cloudflare Access must
-- reach tsidp's public /token and /.well-known/jwks.json. tsidp itself refuses
-- /authorize, its admin UI, /clients and DCR over Funnel. No other tag gets
-- funnel beyond tag:dollhouse (tests/test_policy_contract.py).
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
    = [ { target = [ C.tag.dollhouse ], attr = [ "funnel" ] }
      , { target = [ C.tag.tsidp ], attr = [ "funnel" ] }
      , { target = [ C.tag.anon_gateway ], attr = [ "mullvad" ] }
      ]

let autoApprovers
    : T.AutoApprovers
    = { routes =
        [ { mapKey = "10.0.0.0/8", mapValue = [ C.tag.dollhouse, C.tag.k8s ] }
        , { mapKey = "192.168.0.0/16"
          , mapValue = [ C.tag.subnet_router, C.tag.dollhouse ]
          }
        ]
      , exitNode = [ C.tag.exit_node ]
      , services =
        [ { mapKey = C.service.o11y_loki, mapValue = [ C.tag.mcp_proxy ] }
        , { mapKey = C.service.o11y_tempo, mapValue = [ C.tag.mcp_proxy ] }
        , { mapKey = C.service.o11y_mimir, mapValue = [ C.tag.mcp_proxy ] }
        , { mapKey = C.service.o11y_pyroscope, mapValue = [ C.tag.mcp_proxy ] }
        , { mapKey = C.service.o11y_otlp, mapValue = [ C.tag.mcp_proxy ] }
        , { mapKey = C.service.o11y_grafana, mapValue = [ C.tag.mcp_proxy ] }
        ]
      }

in  { groups = core.groups
    , tagOwners = core.tagOwners
    , acls = allACLs
    , ssh = ssh.ssh
    , nodeAttrs = allNodeAttrs
    , autoApprovers
    , hosts = aperture.hosts # kubernetes.hosts
    }
