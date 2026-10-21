-- Tailscale ACL policy type definitions.
-- These mirror the Tailscale ACL JSON schema exactly.
-- See: https://tailscale.com/kb/1018/acls
--
-- Grants are excluded (handled as raw JSON due to polymorphic app field).
--
-- SSHDenyTest: an sshTests row with only the fields it sets. Tailscale's
-- read-back may drop an empty list and change the canonical digest, so the
-- type gains accept or check only when a test needs a non-empty one.
let ACLRule = { action : Text, src : List Text, dst : List Text }

let SSHRule =
      { action : Text, src : List Text, dst : List Text, users : List Text }

let NodeAttr = { target : List Text, attr : List Text }

let AutoApprovers =
      { routes : List { mapKey : Text, mapValue : List Text }
      , exitNode : List Text
      , services : List { mapKey : Text, mapValue : List Text }
      }

let Host = { mapKey : Text, mapValue : Text }

let ACLTest = { src : Text, proto : Text, accept : List Text, deny : List Text }

let SSHDenyTest = { src : Text, dst : List Text, deny : List Text }

let Group = { mapKey : Text, mapValue : List Text }

let TagOwner = { mapKey : Text, mapValue : List Text }

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
    , ACLTest
    , SSHDenyTest
    , Group
    , TagOwner
    , Fragment
    , Policy
    , emptyFragment
    }
