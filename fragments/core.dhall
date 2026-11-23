-- Core fragment: groups, tag owners, and base user access rules.
-- This is the foundation that all other fragments build on.
--
-- group:gftb-qa (operator ruling 2026-10-03, verbatim: "this is the intent; I
-- can add users to the qa tag as needed."): the one group admitted to the
-- greatfallstoolbus.org membership surface. Users go in groups (devices carry
-- tags), so this is a group, not tag:qa. It starts with the operator's own
-- identities; the operator adds QA users here.
--
-- tag:gftb-idp: the GFTB tsidp node (operator rulings 2026-10-03; lab
-- TAILNET_MEMBERSHIP_DETECTION_DESIGN_2026-10-03.md 4.3). New, so no existing
-- device inherits its grants or Funnel (tag:tsidp is held by several
-- devices). Admin-only owner, like tag:gftb-probe, so no tagged device can
-- mint it next to another tag.
--
-- tag:printstack (R-GOLIVE-20261020-c, operator 2026-10-20, Linear TIN-6787,
-- verbatim: "Approve the tag:printstack ACL change"): the honey Tailscale
-- operator mints the printstack-vision and printstack-mcp Ingress proxies and
-- the printstack-mbp13 egress proxy with it (xoxd-ai/printstack
-- deploy/k8s/*, STAGED.md D7). Owned like tag:mcp-proxy, by tag:k8s-operator
-- plus the admins; tag:k8s-operator itself is not broadened.
--
-- tag:mx-relay: the public MX relay-1 alone (R-C1011, TIN-5770 comment
-- 86411716, from the R-C965 exploration). It replaces tag:dollhouse on that
-- one device so the MX leaves the dollhouse mesh (tag:dollhouse:*) and the
-- dollhouse root Tailscale SSH rule. Owned by autogroup:admin and
-- group:dollhouse-admins only: not tag:tag-authority, so no tagged device
-- can mint it. Its only grants live in fragments/grants.dhall.
--
-- tag:sip-relay: the public SIP relay alone (Linear TIN-7396; Jess, TIN-7125
-- 82432e02 and d1358ace). It joins with one single-use auth key. Owned by
-- autogroup:admin and group:dollhouse-admins, like tag:mx-relay, so a key can
-- be minted with the tailnet admin API key (TIN-7396 7ad85219) and no tagged
-- device can mint it. It owns no tag. Its grants live in
-- fragments/grants.dhall.
--
-- tag:app-edge: a small public edge host (Linear TIN-7649). It follows the
-- tag:sip-relay shape. Owned by autogroup:admin and group:dollhouse-admins
-- only, so no tagged device can mint it. It owns no tag. Its grants live in
-- fragments/grants.dhall.
--
-- tag:murmur-api (Linear TIN-8187). It marks the tailnet device of one
-- Kubernetes Service that the honey Tailscale operator exposes on tcp
-- 8443. No other device carries it. The operator mints it, so it is owned
-- like tag:k8s-egress-nodeexporter, by tag:k8s-operator plus the admins.
-- It owns no tag, and tag:k8s-operator itself is not broadened. Its one
-- grant lives in fragments/grants.dhall.
--
-- tag:murmur-prober and tag:murmur-console (Linear TIN-8188). The tenant
-- that tag:icebox-* serves moves to the murmur name. The icebox name is
-- retired. These two tags are added beside the icebox tags, which stay
-- unchanged until the old namespace is retired.
--   * tag:murmur-prober is the console's lens component. It owns itself,
--     beside autogroup:admin. The operator's pick R-MURMUR-20261118-aq
--     (Linear TIN-7811 87049ff8) has seats mint its single-use keys with
--     an OAuth client that holds tag:murmur-prober and tag:murmur-console.
--     Tailscale lets such a client apply a subset of its tags only when one
--     of its tags owns each requested tag (kb/1068, "Apply a tag from
--     another tag"), so the tag owns itself. Only a holder of
--     tag:murmur-prober can apply it; no other tag gains anything. It owns
--     no other tag.
--   * tag:murmur-console is the console's tailnet Service. The operator
--     mints it, so it is owned like tag:murmur-api, by tag:k8s-operator
--     plus the admins. It owns no tag.
-- Their grants live in fragments/grants.dhall.
--
-- tag:penguincam-dev and tag:penguincam-prod (Linear TIN-8188). The Murmur
-- camera node's device tags. The Murmur tenant's OAuth client holds both and
-- mints the node's single-use key. Tailscale lets a client apply a tag only
-- when one of its own tags owns it, so each tag owns itself beside
-- autogroup:admin, as tag:murmur-prober does. Only a holder of a tag can apply
-- that tag; neither tag owns any other tag. Their grants are in
-- fragments/grants.dhall and their Tailscale SSH rule in fragments/ssh.dhall.
--
-- tag:softproxy (GO-02 step 1, Linear TIN-7729; xoxd-ai/softproxy rulings
-- SP-1 and SP-25): Softproxy's own userspace tailscaled node on honey,
-- joined with one single-use auth key the operator mints. Owned by
-- autogroup:admin alone, like tag:gftb-idp and tag:infra-idp, so no tagged
-- device can mint it. Its one grant lives in fragments/grants.dhall. The
-- grant's sources are group:dollhouse-admins and neo (Jess 2026-10-30,
-- softproxy seat session, TIN-7729).
--
-- tag:softproxy-edge and tag:softproxy-upstream (Linear TIN-7371; SP-133,
-- TIN-7125 comment cd969795; route design xoxd-ai/blahaj#2455). The honey
-- Tailscale operator mints both for the softproxy.xoxd.ai route. The edge
-- is the softproxy-xoxd LoadBalancer device. The upstream is the egress
-- proxy to the softproxy node. Each is owned like tag:mcp-proxy and
-- tag:printstack, by tag:k8s-operator plus the admins. Neither owns a tag,
-- and tag:k8s-operator itself is not broadened. Their two grants live in
-- fragments/grants.dhall.
--
-- tag:cade-hermes-front and tag:cade-hermes-upstream (Linear TIN-7536, GO-04
-- front act 6; packet decision D3, TIN-7536 fba76449; xoxd-ai/blahaj#2505).
-- The front is the Cade Hermes front's own tailscaled node on honey. It joins
-- with one single-use auth key minted from an admin key (D2). It is owned by
-- autogroup:admin alone, like tag:softproxy, so no tagged device can mint it.
-- The upstream is the egress proxy for Service
-- cade-production/cade-hermes-upstream. The honey Tailscale operator mints it,
-- so it is owned like tag:softproxy-upstream. Neither owns a tag, and
-- tag:k8s-operator itself is not broadened. No rule names either tag. The
-- grant is front act 9, after readback R14.
--
-- tag:cade-memory-writer (Linear TIN-7697). It marks the tailnet device of
-- the Tailscale Ingress cade-production/cade-memory-writer, which the honey
-- Tailscale operator mints for the Cade memory writer. tag:k8s-operator owns
-- it so the operator can put it on that device. autogroup:admin owns it so
-- the operator on duty can retag the device by hand. group:dollhouse-admins
-- does not own it, so no member device can advertise it. It owns no tag, and
-- tag:k8s-operator itself is not broadened. Its one grant lives in
-- fragments/cade-memory.dhall.
--
-- tag:annotate, tag:annotate-edge and tag:annotate-upstream (Linear
-- TIN-8117; Jess, comments 54098524 and ab8be277; route design
-- xoxd-ai/blahaj#2566, precondition P1a). tag:annotate is the annotation
-- page's own userspace tailscaled node on sting, host name annotate. A
-- tailnet admin enrols it once. It is owned by autogroup:admin alone, like
-- tag:softproxy, so no tagged device can mint it. The edge is the
-- annotate-xoxd LoadBalancer device and the upstream is the egress proxy to
-- the node. The honey Tailscale operator mints both, so each is owned like
-- the softproxy route tags. None owns a tag, and tag:k8s-operator itself is
-- not broadened. Their grants live in fragments/grants.dhall.
--
-- tag:gf-pool-cell-egress (Linear TIN-8468; rulings R816 and R819, comments
-- 2de8bcb4 and 496f4843). The honey Tailscale operator's egress proxy for
-- the GloriousFlywheel pool cell in namespace gf-pool. The operator mints
-- it, so it is owned like tag:gf-reapi-cell-egress. It is a tag of its own
-- because tag:gf-reapi-cell-egress is the gf-rbe cell's proxy, and the pool
-- runs other organizations' build actions. It owns no tag, and
-- tag:k8s-operator itself is not broadened. Its grant lives in
-- fragments/grants.dhall.
--
-- tag:gf-developer (Linear TIN-8469). It marks the tailnet device of one
-- Kubernetes Service, the GloriousFlywheel cell's developer surface on
-- honey, which the honey Tailscale operator exposes on tcp 443. No other
-- device carries it. It is a tag of its own so that reach to it is not
-- shared with every device on tag:k8s. The operator mints it, so it is
-- owned like tag:murmur-api, by tag:k8s-operator plus the admins. It owns
-- no tag, and tag:k8s-operator itself is not broadened. Its one grant
-- lives in fragments/grants.dhall.
--
-- icebox (Linear TIN-7812, Jess's rulings IB-1 and IB-3 to IB-7 in comments
-- b0d7c34e and ba40e1a6; folds Jesssullivan/tailnet-acl#65, TIN-7811;
-- xoxd-ai/icebox is owned by the PZM icebox seat under
-- R-ICEBOX-20261030-a; IB-10 for tag:icebox-member). Four groups and five
-- tags:
--   * group:icebox-dev holds the developers. group:icebox-prod holds every
--     dev member (IB-1). Tailscale groups cannot nest, so both lists come
--     from one Dhall list. The contract test pins dev as a subset of prod.
--   * group:icebox-dispatchers and group:icebox-keyholders are the
--     dispatcher console roles from #65. Keyholders add members here.
--   * tag:icebox-dev marks bench devices and tag:icebox-prod deployed
--     devices. They replace #65's tag:icebox. tag:icebox-console is the
--     console and ingest node, and tag:icebox-prober is the device prober.
--   * tag:icebox-member marks an icebox member's own device (IB-10,
--     "Tag-based access instead"). It reaches what group:icebox-prod
--     reaches, and every port on tag:icebox-dev.
--     autogroup:admin alone owns each tag (Q5), so no tagged device can
--     mint one.
-- Every group starts with Jess's two identities. Under IB-10 an invitee
-- joins by tagging a device tag:icebox-member, so no personal address
-- enters this public file. The icebox rows live in fragments/grants.dhall and
-- fragments/ssh.dhall.
let T = ../types/ACL.dhall

let C = ../constants.dhall

let iceboxDevMembers = [ C.user.jsullivan2_gmail, C.user.jess_sulliwood ]

let groups
    : List T.Group
    = [ { mapKey = C.group.dollhouse_users
        , mapValue = [ C.user.jsullivan2_gmail, C.user.jess_sulliwood ]
        }
      , { mapKey = C.group.dollhouse_admins
        , mapValue = [ C.user.jsullivan2_gmail, C.user.jess_sulliwood ]
        }
      , { mapKey = C.group.developers
        , mapValue = [ C.user.jsullivan2_gmail, C.user.jess_sulliwood ]
        }
      , { mapKey = C.group.gftb_qa
        , mapValue = [ C.user.jsullivan2_gmail, C.user.jess_sulliwood ]
        }
      , { mapKey = C.group.icebox_dev, mapValue = iceboxDevMembers }
      , { mapKey = C.group.icebox_prod, mapValue = iceboxDevMembers }
      , { mapKey = C.group.icebox_dispatchers
        , mapValue = [ C.user.jsullivan2_gmail, C.user.jess_sulliwood ]
        }
      , { mapKey = C.group.icebox_keyholders
        , mapValue = [ C.user.jsullivan2_gmail, C.user.jess_sulliwood ]
        }
      ]

let tagOwners
    : List T.TagOwner
    = [ { mapKey = C.tag.dollhouse
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.services
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.interim_build
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.honey_relay
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.mx_relay
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.sip_relay
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.app_edge
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.murmur_api
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.murmur_prober
        , mapValue = [ C.tag.murmur_prober, C.autogroup.admin ]
        }
      , { mapKey = C.tag.murmur_console
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.penguincam_dev
        , mapValue = [ C.tag.penguincam_dev, C.autogroup.admin ]
        }
      , { mapKey = C.tag.penguincam_prod
        , mapValue = [ C.tag.penguincam_prod, C.autogroup.admin ]
        }
      , { mapKey = C.tag.gf_reapi_cell_egress
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.gf_reapi_linux_worker
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.gf_reapi_rocm_worker
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.gf_pool_cell_egress
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.gf_developer
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.k8s
        , mapValue =
          [ C.tag.tag_authority
          , C.tag.k8s_operator
          , C.autogroup.admin
          , C.group.dollhouse_admins
          ]
        }
      , { mapKey = C.tag.k8s_operator
        , mapValue =
          [ C.tag.tag_authority
          , C.tag.k8s_operator
          , C.autogroup.admin
          , C.group.dollhouse_admins
          ]
        }
      , { mapKey = C.tag.mcp_proxy
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.k8s_egress_nodeexporter
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tsidp
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.gftb_probe, mapValue = [ C.autogroup.admin ] }
      , { mapKey = C.tag.dev
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.developers ]
        }
      , { mapKey = C.tag.staging
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.developers ]
        }
      , { mapKey = C.tag.qa
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.developers ]
        }
      , { mapKey = C.tag.anon_gateway, mapValue = [ C.autogroup.admin ] }
      , { mapKey = C.tag.exit_node
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.switch
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.subnet_router
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tinyland_lab_common
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tinyland_lab_sunshine
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tinyland_lab_moonlight
        , mapValue =
          [ C.tag.tag_authority, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tinyland_lab_crush
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tinyland_lab_runner
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tinyland_lab_deploy
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tinyland_lab_ci_ephemeral
        , mapValue = [ C.tag.tinyland_lab_deploy, C.autogroup.admin ]
        }
      , { mapKey = C.tag.tinyland_lab_nix_target
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.ci_agent
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.kvm_proxy
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.tag_authority
        , mapValue = [ C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.gftb_idp, mapValue = [ C.autogroup.admin ] }
      , { mapKey = C.tag.infra_idp, mapValue = [ C.autogroup.admin ] }
      , { mapKey = C.tag.tofu_state
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.printstack
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.softproxy, mapValue = [ C.autogroup.admin ] }
      , { mapKey = C.tag.softproxy_edge
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.softproxy_upstream
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.cade_hermes_front, mapValue = [ C.autogroup.admin ] }
      , { mapKey = C.tag.cade_hermes_upstream
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.cade_memory_writer
        , mapValue = [ C.tag.k8s_operator, C.autogroup.admin ]
        }
      , { mapKey = C.tag.annotate, mapValue = [ C.autogroup.admin ] }
      , { mapKey = C.tag.annotate_edge
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.annotate_upstream
        , mapValue =
          [ C.tag.k8s_operator, C.autogroup.admin, C.group.dollhouse_admins ]
        }
      , { mapKey = C.tag.icebox_dev, mapValue = [ C.autogroup.admin ] }
      , { mapKey = C.tag.icebox_prod, mapValue = [ C.autogroup.admin ] }
      , { mapKey = C.tag.icebox_prober, mapValue = [ C.autogroup.admin ] }
      , { mapKey = C.tag.icebox_console, mapValue = [ C.autogroup.admin ] }
      , { mapKey = C.tag.icebox_member, mapValue = [ C.autogroup.admin ] }
      ]

let acls
    : List T.ACLRule
    = [ { action = "accept"
        , src = [ C.group.dollhouse_users, C.group.dollhouse_admins ]
        , dst = [ "${C.tag.dev}:*", "${C.tag.dollhouse}:*" ]
        }
      ]

in  { groups, tagOwners, acls }
