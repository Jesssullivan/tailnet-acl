-- Typed grants. Ported 1:1 from the former raw grants.json; order is
-- significant (it is the order in the rendered policy).
--
-- tailscale.com/cap/kubernetes (R-C557, TIN-6192 comment 94eb75c0; R-C560,
-- TIN-6192 comment aa9f7910).
-- honey's operator API server proxy (ts-operator-honey, tag:k8s-operator,
-- :443) reads this cap from WhoIs of the CALLER, so a cap reaches it only
-- through a grant with src = caller and dst = proxy tag (upstream shape:
-- tailscale cmd/k8s-operator/e2e/acl.hujson). The cap is inert until blahaj
-- sets apiServerProxyConfig.mode to "true" (auth mode).
--   * adi-sms-deployers, R-C557 "Tailscale API proxy, auth mode
--     (Recommended)": tag:tinyland-lab-ci-ephemeral reaches tag:k8s-operator
--     on tcp:443 only and is impersonated as that one group, which blahaj
--     binds by a RoleBinding in namespace adi-sms only.
--   * No grant impersonates system:masters. R-C560 "Delete it
--     (Recommended)" removed the reversed, inert tag:k8s-operator ->
--     jess@sulliwood.org row that R-C558 had narrowed. Cluster-admin stays
--     on direct :6443 with a kubeconfig; the proxy serves only scoped CI
--     groups.
--   * Every value is held to scripts/kubernetes_cap.py (R-C562 follow-up,
--     TIN-6192 comments 789060b4 and 7fdfcb61): never the legacy
--     https://tailscale.com/cap/kubernetes name, and only
--     [{"impersonate": {"groups": [<non-system groups>]}}]. Upstream v1.102.4
--     forwards as the operator ServiceAccount when a value fails to decode.
--     `just build`, the trusted CI driver and push.py all refuse otherwise.
--
-- Relay log shipper (TIN-6746 P4, blahaj relay-log-shipper runbook): the
-- public MX relay-1 pushes its journal, fail2ban and nginx logs to the
-- write-only loki-push Tailscale ingress (tag:k8s device 100.85.50.69,
-- blahaj deploy/honey/retained-observability-tailnet-services.yaml) on
-- tcp:443 only. relay-1 is tag:dollhouse today, so R-W52's
-- tag:dollhouse -> tag:k8s:443 already admits it; this exact host-to-host
-- grant keeps the shipper working if the relay's tag is ever narrowed, and
-- names the dependency. Pinned by tests/test_policy_contract.py and by a
-- policy test in fragments/tests.dhall.
let C = ../constants.dhall

let G = ../types/Grant.dhall

let J = ../types/JSON.dhall

let grants
    : List G.Grant
    = [ G.cap
          [ C.tag.tsidp ]
          [ C.group.dollhouse_admins ]
          [ G.Cap.Tsidp
              (G.tsidpEmpty // { admin = Some [ C.group.dollhouse_admins ] })
          ]
      , G.cap
          [ C.group.dollhouse_admins ]
          [ C.tag.gftb_idp ]
          [ G.Cap.Tsidp (G.tsidpEmpty // { allowAdminUI = Some True }) ]
      , G.cap
          [ C.group.gftb_qa ]
          [ C.tag.gftb_idp ]
          [ G.Cap.Tsidp
              (     G.tsidpEmpty
                //  { extraClaims = Some
                      [ { mapKey = "gftb_member", mapValue = J.string "true" } ]
                    , includeInUserInfo = Some True
                    }
              )
          ]
      , G.net [ C.group.gftb_qa ] [ C.tag.gftb_idp ] [ "tcp:443" ]
      , G.net [ "tinyland-neo" ] [ C.tag.gftb_idp ] [ "tcp:443" ]
      , G.cap
          [ "tinyland-neo" ]
          [ C.tag.gftb_idp ]
          [ G.Cap.Tsidp (G.tsidpEmpty // { allowAdminUI = Some True }) ]
      , G.cap
          [ "tinyland-neo" ]
          [ C.tag.gftb_idp ]
          [ G.Cap.Tsidp
              (     G.tsidpEmpty
                //  { extraClaims = Some
                      [ { mapKey = "gftb_member", mapValue = J.string "true" } ]
                    , includeInUserInfo = Some True
                    , taggedIdentity = Some
                      { subject = "16908883666124"
                      , email = "jess@sulliwood.org"
                      , name = "Jess Sullivan"
                      }
                    }
              )
          ]
      , G.cap
          [ C.autogroup.member ]
          [ C.tag.rj_gateway ]
          [ G.Cap.RjGateway { role = "reader", secrets = None (List Text) } ]
      , G.cap
          [ C.autogroup.admin ]
          [ C.tag.rj_gateway ]
          [ G.Cap.RjGateway { role = "admin", secrets = None (List Text) } ]
      , G.cap
          [ C.tag.ci_agent ]
          [ C.tag.rj_gateway ]
          [ G.Cap.RjGateway
              { role = "reader"
              , secrets = Some
                [ "github-token", "gitlab-token", "neon-database-url" ]
              }
          ]
      , G.cap
          [ C.tag.rj_gateway ]
          [ C.tag.setec ]
          [ G.Cap.Secrets
              { action = [ "get", "info", "put", "activate", "delete" ]
              , secret = [ "*" ]
              }
          ]
      , G.cap
          [ C.autogroup.admin ]
          [ C.tag.setec ]
          [ G.Cap.Secrets
              { action = [ "get", "info", "put", "activate", "delete" ]
              , secret = [ "*" ]
              }
          ]
      , G.net [ "tinyland-honey" ] [ C.tag.mcp_proxy ] [ "tcp:8080" ]
      , G.net
          [ "tinyland-honey" ]
          [ "tinyland-mcp-arxiv"
          , "tinyland-mcp-duckduckgo"
          , "tinyland-mcp-fetch"
          , "tinyland-mcp-paper-search"
          , "tinyland-mcp-wikipedia"
          ]
          [ "tcp:8080" ]
      , G.net
          [ C.group.dollhouse_admins, C.tag.mcp_proxy ]
          [ C.tag.mcp_proxy ]
          [ "tcp:3100", "tcp:3200" ]
      , G.net
          [ "tinyland-honey"
          , "tinyland-bumble"
          , "tinyland-sting"
          , "tinyland-petting-zoo-mini"
          ]
          [ C.tag.mcp_proxy ]
          [ "tcp:3100" ]
      , G.net
          [ C.group.dollhouse_admins, C.tag.mcp_proxy ]
          [ C.tag.mcp_proxy ]
          [ "tcp:9009" ]
      , G.net
          [ C.group.dollhouse_admins, C.tag.mcp_proxy ]
          [ C.tag.mcp_proxy ]
          [ "tcp:4040" ]
      , G.net
          [ C.group.dollhouse_admins
          , C.group.dollhouse_users
          , C.tag.k8s
          , C.tag.k8s_operator
          , C.tag.dev
          , C.tag.ci_agent
          ]
          [ C.tag.mcp_proxy ]
          [ "tcp:4318" ]
      , G.net
          [ C.group.dollhouse_admins
          , C.group.dollhouse_users
          , C.tag.k8s
          , C.tag.k8s_operator
          , C.tag.dev
          , C.tag.ci_agent
          , "tinyland-honey"
          ]
          [ C.tag.mcp_proxy ]
          [ "tcp:3000" ]
      , G.net
          [ C.tag.k8s_egress_nodeexporter ]
          [ "tinyland-relay-1", "tinyland-petting-zoo-mini", "tinyland-neo" ]
          [ "tcp:9100" ]
      , G.net [ "tinyland-relay-1" ] [ "tinyland-loki-push" ] [ "tcp:443" ]
      , G.cap [ C.tag.dollhouse ] [ C.tag.dollhouse ] [ G.Cap.Relay ]
      , G.cap [ C.tag.interim_build ] [ C.tag.honey_relay ] [ G.Cap.Relay ]
      , G.net
          [ C.group.dollhouse_admins, C.tag.mcp_proxy ]
          [ C.service.o11y_loki ]
          [ "tcp:3100" ]
      , G.net
          [ C.group.dollhouse_admins, C.tag.mcp_proxy ]
          [ C.service.o11y_tempo ]
          [ "tcp:3200" ]
      , G.net
          [ C.group.dollhouse_admins, C.tag.mcp_proxy ]
          [ C.service.o11y_mimir ]
          [ "tcp:9009" ]
      , G.net
          [ C.group.dollhouse_admins, C.tag.mcp_proxy ]
          [ C.service.o11y_pyroscope ]
          [ "tcp:4040" ]
      , G.net
          [ "tinyland-honey"
          , "tinyland-bumble"
          , "tinyland-sting"
          , "tinyland-petting-zoo-mini"
          ]
          [ C.service.o11y_loki ]
          [ "tcp:3100" ]
      , G.net
          [ C.group.dollhouse_admins
          , C.group.dollhouse_users
          , C.tag.k8s
          , C.tag.k8s_operator
          , C.tag.dev
          , C.tag.ci_agent
          ]
          [ C.service.o11y_otlp ]
          [ "tcp:4318" ]
      , G.net
          [ C.group.dollhouse_admins
          , C.group.dollhouse_users
          , C.tag.k8s
          , C.tag.k8s_operator
          , C.tag.dev
          , C.tag.ci_agent
          , "tinyland-honey"
          ]
          [ C.service.o11y_grafana ]
          [ "tcp:3000" ]
      , { src = [ C.group.gftb_qa ]
        , dst = [ C.tag.gftb_probe ]
        , ip = Some [ "tcp:443" ]
        , app = Some
          [ G.Cap.Probe
              { cap = "greatfallstoolbus.org/cap/gftb-probe", flag = "gftb_qa" }
          ]
        }
      , { src = [ "tinyland-neo" ]
        , dst = [ C.tag.gftb_probe ]
        , ip = Some [ "tcp:443" ]
        , app = Some
          [ G.Cap.ProbeUser
              { cap = "greatfallstoolbus.org/cap/gftb-probe"
              , flag = "gftb_qa"
              , user = "jess@sulliwood.org"
              }
          ]
        }
      , G.net [ C.autogroup.admin ] [ C.tag.tofu_state ] [ "tcp:9000" ]
      , G.net [ "tinyland-neo" ] [ C.tag.tofu_state ] [ "tcp:9000" ]
      , G.net
          [ C.group.dollhouse_admins, C.tag.k8s ]
          [ C.tag.infra_idp ]
          [ "tcp:443" ]
      , G.cap
          [ C.group.dollhouse_admins ]
          [ C.tag.infra_idp ]
          [ G.Cap.Tsidp (G.tsidpEmpty // { allowAdminUI = Some True }) ]
      , G.net
          [ C.tag.gf_reapi_cell_egress ]
          [ C.tag.gf_reapi_linux_worker ]
          [ "tcp:8981" ]
      , G.net
          [ C.tag.gf_reapi_cell_egress ]
          [ C.tag.gf_reapi_rocm_worker ]
          [ "tcp:8981" ]
      , { src = [ C.tag.tinyland_lab_ci_ephemeral ]
        , dst = [ C.tag.k8s_operator ]
        , ip = Some [ "tcp:443" ]
        , app = Some
          [ G.Cap.Kubernetes { impersonateGroups = [ "adi-sms-deployers" ] } ]
        }
      ]

in  { grants }
