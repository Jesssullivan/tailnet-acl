-- Typed Tailscale grants.
--
-- A grant's `app` field is polymorphic (capability name -> list of arbitrary
-- objects), so it is modelled as a union of known capability shapes plus a
-- Custom escape hatch carrying raw JSON (types/JSON.dhall, the Prelude JSON
-- encoding). `render` turns List Grant into the JSON the policy expects;
-- absent Optional fields are omitted, never emitted as null.
--
-- `via` and `srcPosture` are valid grant fields but no grant here uses them,
-- so they are not modelled yet.
let J = ./JSON.dhall

let Entry = { mapKey : Text, mapValue : J.Type }

let Tsidp =
      { admin : Optional (List Text)
      , extraClaims : Optional (List { mapKey : Text, mapValue : J.Type })
      , includeInUserInfo : Optional Bool
      , allowAdminUI : Optional Bool
      , allowDCR : Optional Bool
      , users : Optional (List Text)
      , resources : Optional (List Text)
      }

let tsidpEmpty
    : Tsidp
    = { admin = None (List Text)
      , extraClaims = None (List { mapKey : Text, mapValue : J.Type })
      , includeInUserInfo = None Bool
      , allowAdminUI = None Bool
      , allowDCR = None Bool
      , users = None (List Text)
      , resources = None (List Text)
      }

let Cap =
      < Probe : { cap : Text, flag : Text }
      | ProbeUser : { cap : Text, flag : Text, user : Text }
      | Tsidp : Tsidp
      | Kubernetes : { impersonateGroups : List Text }
      | RjGateway : { role : Text, secrets : Optional (List Text) }
      | Secrets : { action : List Text, secret : List Text }
      | Relay
      | Custom : { name : Text, json : J.Type }
      >

let Grant =
      { src : List Text
      , dst : List Text
      , ip : Optional (List Text)
      , app : Optional (List Cap)
      }

let toList =
      \(a : Type) ->
      \(o : Optional a) ->
        merge { Some = \(x : a) -> [ x ], None = [] : List a } o

let field =
      \(a : Type) ->
      \(key : Text) ->
      \(f : a -> J.Type) ->
      \(o : Optional a) ->
        J.map
          a
          Entry
          (\(x : a) -> { mapKey = key, mapValue = f x })
          (toList a o)

let none = [] : List Entry

let renderTsidp
    : Tsidp -> J.Type
    = \(t : Tsidp) ->
        J.object
          (   field (List Text) "admin" J.strings t.admin
            # field
                (List { mapKey : Text, mapValue : J.Type })
                "extraClaims"
                J.object
                t.extraClaims
            # field Bool "includeInUserInfo" J.bool t.includeInUserInfo
            # field Bool "allow_admin_ui" J.bool t.allowAdminUI
            # field Bool "allow_dcr" J.bool t.allowDCR
            # field (List Text) "users" J.strings t.users
            # field (List Text) "resources" J.strings t.resources
          )

let renderCap
    : Cap -> Entry
    = \(c : Cap) ->
        merge
          { Probe =
              \(p : { cap : Text, flag : Text }) ->
                { mapKey = p.cap
                , mapValue =
                    J.array
                      [ J.object [ { mapKey = p.flag, mapValue = J.bool True } ]
                      ]
                }
          , ProbeUser =
              \(p : { cap : Text, flag : Text, user : Text }) ->
                { mapKey = p.cap
                , mapValue =
                    J.array
                      [ J.object
                          [ { mapKey = p.flag, mapValue = J.bool True }
                          , { mapKey = "user", mapValue = J.string p.user }
                          ]
                      ]
                }
          , Tsidp =
              \(t : Tsidp) ->
                { mapKey = "tailscale.com/cap/tsidp"
                , mapValue = J.array [ renderTsidp t ]
                }
          , Kubernetes =
              \(k : { impersonateGroups : List Text }) ->
                { mapKey = "tailscale.com/cap/kubernetes"
                , mapValue =
                    J.array
                      [ J.object
                          [ { mapKey = "impersonate"
                            , mapValue =
                                J.object
                                  [ { mapKey = "groups"
                                    , mapValue = J.strings k.impersonateGroups
                                    }
                                  ]
                            }
                          ]
                      ]
                }
          , RjGateway =
              \(r : { role : Text, secrets : Optional (List Text) }) ->
                { mapKey = "tinyland.dev/cap/rj-gateway"
                , mapValue =
                    J.array
                      [ J.object
                          (   [ { mapKey = "role", mapValue = J.string r.role }
                              ]
                            # field (List Text) "secrets" J.strings r.secrets
                          )
                      ]
                }
          , Secrets =
              \(s : { action : List Text, secret : List Text }) ->
                { mapKey = "tailscale.com/cap/secrets"
                , mapValue =
                    J.array
                      [ J.object
                          [ { mapKey = "action", mapValue = J.strings s.action }
                          , { mapKey = "secret", mapValue = J.strings s.secret }
                          ]
                      ]
                }
          , Relay =
            { mapKey = "tailscale.com/cap/relay"
            , mapValue = J.array [ J.object none ]
            }
          , Custom =
              \(x : { name : Text, json : J.Type }) ->
                { mapKey = x.name, mapValue = x.json }
          }
          c

let renderGrant
    : Grant -> J.Type
    = \(g : Grant) ->
        J.object
          (   [ { mapKey = "src", mapValue = J.strings g.src }
              , { mapKey = "dst", mapValue = J.strings g.dst }
              ]
            # field (List Text) "ip" J.strings g.ip
            # field
                (List Cap)
                "app"
                ( \(caps : List Cap) ->
                    J.object (J.map Cap Entry renderCap caps)
                )
                g.app
          )

let render
    : List Grant -> List J.Type
    = J.map Grant J.Type renderGrant

let net =
      \(src : List Text) ->
      \(dst : List Text) ->
      \(ip : List Text) ->
        { src, dst, ip = Some ip, app = None (List Cap) } : Grant

let cap =
      \(src : List Text) ->
      \(dst : List Text) ->
      \(caps : List Cap) ->
        { src, dst, ip = None (List Text), app = Some caps } : Grant

in  { Cap, Grant, Tsidp, tsidpEmpty, render, net, cap }
