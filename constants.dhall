-- Shared constants for the tailnet ACL.
-- All tag names, group names, and user emails are defined here
-- so that typos are caught by the Dhall type checker.

-- Users
let user =
      { jsullivan2_gmail = "jsullivan2@gmail.com"
      , jess_sulliwood = "jess@sulliwood.org"
      }

let group =
      { dollhouse_users = "group:dollhouse-users"
      , dollhouse_admins = "group:dollhouse-admins"
      , developers = "group:developers"
      }

let autogroup =
      { admin = "autogroup:admin"
      , member = "autogroup:member"
      , internet = "autogroup:internet"
      , nonroot = "autogroup:nonroot"
      }

let tag =
      { dollhouse = "tag:dollhouse"
      , services = "tag:services"
      , k8s = "tag:k8s"
      , k8s_operator = "tag:k8s-operator"
      , mcp_proxy = "tag:mcp-proxy"
      , k8s_egress_nodeexporter = "tag:k8s-egress-nodeexporter"
      , tsidp = "tag:tsidp"
      , dev = "tag:dev"
      , staging = "tag:staging"
      , qa = "tag:qa"
      , anon_gateway = "tag:anon-gateway"
      , exit_node = "tag:exit-node"
      , switch = "tag:switch"
      , subnet_router = "tag:subnet-router"
      , tinyland_lab_common = "tag:tinyland-lab-common"
      , tinyland_lab_sunshine = "tag:tinyland-lab-sunshine"
      , tinyland_lab_moonlight = "tag:tinyland-lab-moonlight"
      , tinyland_lab_crush = "tag:tinyland-lab-crush"
      , tinyland_lab_runner = "tag:tinyland-lab-runner"
      , tinyland_lab_deploy = "tag:tinyland-lab-deploy"
      , tinyland_lab_ci_ephemeral = "tag:tinyland-lab-ci-ephemeral"
      , tinyland_lab_nix_target = "tag:tinyland-lab-nix-target"
      , rj_gateway = "tag:rj-gateway"
      , setec = "tag:setec"
      , ci_agent = "tag:ci-agent"
      , kvm_proxy = "tag:kvm-proxy"
      , tag_authority = "tag:tag-authority"
      }

let host =
      { ai = "100.108.97.127"
      , honey = "100.113.89.12"
      , bumble = "100.88.101.107"
      , sting = "100.85.46.118"
      , loki_observability = "100.64.15.87"
      , grafana_observability = "100.74.127.80"
      , relay_1 = "100.102.229.122"
      , petting_zoo_mini = "100.111.5.80"
      , neo = "100.67.93.34"
      -- Interim, lab TIN-4415 (2026-09-19): the five blahaj mcp-services proxies
      -- as host aliases so tinyland-honey can reach them on tcp/8080. The
      -- intended shape is the existing tag-scoped grant (tinyland-honey ->
      -- tag:mcp-proxy), but the Tailscale operator never applied
      -- tailscale.com/tags=tag:mcp-proxy to these proxies (blahaj drift), so
      -- they carry tag:k8s only. Retire these aliases and the grant that uses
      -- them once the proxies are re-registered with tag:mcp-proxy.
      , mcp_arxiv = "100.75.221.65"
      , mcp_duckduckgo = "100.69.247.122"
      , mcp_fetch = "100.66.235.11"
      , mcp_paper_search = "100.77.215.50"
      , mcp_wikipedia = "100.78.235.88"
      }

in  { user, group, autogroup, tag, host }
