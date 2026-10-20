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
-- tag:mx-relay, the public MX relay-1 (R-C1011, TIN-5770 comment 86411716;
-- exploration blahaj #2328). These five rows are the tag's only rules, and
-- they are additive: tag:dollhouse and every other rule are unchanged. They
-- take effect when the operator retags relay-1 from tag:dollhouse to
-- tag:mx-relay in an attended window; until then the dollhouse mesh still
-- carries the same flows.
--   * honey -> relay on tcp 22 (offsite-irreplaceable push, OpenSSH; the
--     relay does not run Tailscale SSH), 25 (postfix relayhost), 9100 and
--     9154 (prometheus-mail scrapes, honey pod SNAT).
--   * neo and group:dollhouse-admins -> relay on tcp 22 only. The group row
--     IS the untagged break-glass path: a group source matches only untagged
--     devices owned by its members, so R-C1011's "dollhouse-admins" and
--     "untagged break-glass" sources collapse into one row on purpose.
--   * relay -> honey on tcp 25 (inbound transport) and 465 (Gmail send-as).
--   * relay -> the write-only loki-push ingress on tcp 443 (the relay log
--     shipper, TIN-6746 P4; this supersedes tailnet-acl#55, R-C964).
-- Retired: no grant lets neo, sting or bumble reach relay:25. SMTP probes go
-- through honey's postfix (inject with sendmail/postdrop in postfix-0; lab's
-- F7 fence admits relay:25 from socket uid 89 only and drops honey's pod
-- CIDR) or run on relay loopback. tag:mx-relay has no SSH rule, nodeAttr or
-- autoApprover (Tailscale SSH stays off on the relay; R-C1016 keeps its
-- local AdvertiseTags until the next rebuild).
-- Kept on purpose, outside R-C1011's list (flagged for the operator):
-- tag:k8s-egress-nodeexporter -> tinyland-relay-1:9100 above, the existing
-- observability Prometheus node-exporter scrape through the egress proxy
-- (TIN-4324). It keys on the relay alias, so it survives the retag
-- unchanged; keeping it changes nothing.
-- IPv4 only: the tinyland-* host aliases are IPv4 literals, so the honey,
-- neo and loki-push ends of these rows admit IPv4 only. Every client of
-- these flows dials an IPv4 literal; a client pointed at a MagicDNS name
-- (AAAA first) would time out, and that is not an ACL bug.
-- tag:dollhouse and its rules are out of scope here (R-C1017). Pinned by
-- tests/test_policy_contract.py and by policy tests in fragments/tests.dhall.
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
      , G.net
          [ "tinyland-honey" ]
          [ C.tag.mx_relay ]
          [ "tcp:22", "tcp:25", "tcp:9100", "tcp:9154" ]
      , G.net [ "tinyland-neo" ] [ C.tag.mx_relay ] [ "tcp:22" ]
      , G.net [ C.group.dollhouse_admins ] [ C.tag.mx_relay ] [ "tcp:22" ]
      , G.net [ C.tag.mx_relay ] [ "tinyland-honey" ] [ "tcp:25", "tcp:465" ]
      , G.net [ C.tag.mx_relay ] [ "tinyland-loki-push" ] [ "tcp:443" ]
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
