-- Shared constants for the tailnet ACL.
-- All tag names, group names, and user emails are defined here
-- so that typos are caught by the Dhall type checker.

-- Users
let user =
      { jsullivan2_gmail = "jsullivan2@gmail.com"
      , jess_sulliwood = "jess@sulliwood.org"
      }

-- Groups (with the "group:" prefix baked in)
let group =
      { dollhouse_users = "group:dollhouse-users"
      , dollhouse_admins = "group:dollhouse-admins"
      , developers = "group:developers"
      , qa_engineers = "group:qa-engineers"
      }

-- Autogroups
let autogroup =
      { admin = "autogroup:admin"
      , member = "autogroup:member"
      , internet = "autogroup:internet"
      , nonroot = "autogroup:nonroot"
      }

-- Tags (with the "tag:" prefix baked in)
let tag =
      { dollhouse = "tag:dollhouse"
      , services = "tag:services"
      , k8s = "tag:k8s"
      , k8s_operator = "tag:k8s-operator"
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
      , tinyland_lab_dev = "tag:tinyland-lab-dev"
      , tinyland_lab_deploy = "tag:tinyland-lab-deploy"
      , tinyland_lab_ci_ephemeral = "tag:tinyland-lab-ci-ephemeral"
      , tinyland_lab_nix_target = "tag:tinyland-lab-nix-target"
      , rj_gateway = "tag:rj-gateway"
      , setec = "tag:setec"
      , ci_agent = "tag:ci-agent"
      }

-- Hosts
let host = { ai = "100.108.97.127" }

in  { user, group, autogroup, tag, host }
