-- Tailscale ACL policy type definitions.
-- These mirror the Tailscale ACL JSON schema exactly.
-- See: https://tailscale.com/kb/1018/acls
--
-- Grants are excluded (handled as raw JSON due to polymorphic app field).

let ACLRule =
      { action : Text
      , src : List Text
      , dst : List Text
      }

let SSHRule =
      { action : Text
      , src : List Text
      , dst : List Text
      , users : List Text
      }

let NodeAttr =
      { target : List Text
      , attr : List Text
      }

let AutoApprovers =
      { routes : List { mapKey : Text, mapValue : List Text }
      , exitNode : List Text
      }

let Host = { mapKey : Text, mapValue : Text }

let Group = { mapKey : Text, mapValue : List Text }

let TagOwner = { mapKey : Text, mapValue : List Text }

-- A Fragment is a composable piece of ACL policy.
-- Fragments are merged to produce the final ACL.
-- Grants are NOT included here (they live in grants.json).
let Fragment =
      { groups : List Group
      , tagOwners : List TagOwner
      , acls : List ACLRule
      , ssh : List SSHRule
      , hosts : List Host
      , nodeAttrs : List NodeAttr
      }

let emptyFragment
    : Fragment
    = { groups = [] : List Group
      , tagOwners = [] : List TagOwner
      , acls = [] : List ACLRule
      , ssh = [] : List SSHRule
      , hosts = [] : List Host
      , nodeAttrs = [] : List NodeAttr
      }

-- The full Tailscale ACL policy (output format, minus grants).
-- build.py merges this with grants.json to produce the final policy.
let Policy =
      { groups : List Group
      , tagOwners : List TagOwner
      , acls : List ACLRule
      , ssh : List SSHRule
      , hosts : List Host
      , nodeAttrs : List NodeAttr
      , autoApprovers : AutoApprovers
      }

in  { ACLRule
    , SSHRule
    , NodeAttr
    , AutoApprovers
    , Host
    , Group
    , TagOwner
    , Fragment
    , Policy
    , emptyFragment
    }
