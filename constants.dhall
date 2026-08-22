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
      , neo = "100.67.93.34"
      , relay_1 = "100.102.229.122"
      , petting_zoo_mini = "100.111.5.80"
      }

in  { user, group, autogroup, tag, host }
