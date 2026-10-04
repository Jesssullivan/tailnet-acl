-- Minimal vendored copy of the dhall-lang Prelude JSON encoding
-- (Prelude/JSON/Type and constructors). The policy source contract only
-- admits local imports (scripts/policy_source.py), so the Prelude cannot be
-- imported by URL. Type is structurally identical to Prelude.JSON.Type, so
-- dhall-to-json renders it natively and a later switch to the Prelude import
-- is a drop-in replacement.
-- Prelude List/map, inlined for the same reason.
let map
    : forall (a : Type) -> forall (b : Type) -> (a -> b) -> List a -> List b
    = \(a : Type) ->
      \(b : Type) ->
      \(f : a -> b) ->
      \(xs : List a) ->
        List/build
          b
          ( \(list : Type) ->
            \(cons : b -> list -> list) ->
            \(nil : list) ->
              List/fold a xs list (\(x : a) -> \(y : list) -> cons (f x) y) nil
          )

let Json =
      forall (JSON : Type) ->
      forall  ( json
              : { array : List JSON -> JSON
                , bool : Bool -> JSON
                , null : JSON
                , number : Double -> JSON
                , object : List { mapKey : Text, mapValue : JSON } -> JSON
                , string : Text -> JSON
                }
              ) ->
        JSON

let string
    : Text -> Json
    = \(x : Text) ->
      \(JSON : Type) ->
      \ ( json
        : { array : List JSON -> JSON
          , bool : Bool -> JSON
          , null : JSON
          , number : Double -> JSON
          , object : List { mapKey : Text, mapValue : JSON } -> JSON
          , string : Text -> JSON
          }
        ) ->
        json.string x

let bool
    : Bool -> Json
    = \(x : Bool) ->
      \(JSON : Type) ->
      \ ( json
        : { array : List JSON -> JSON
          , bool : Bool -> JSON
          , null : JSON
          , number : Double -> JSON
          , object : List { mapKey : Text, mapValue : JSON } -> JSON
          , string : Text -> JSON
          }
        ) ->
        json.bool x

let number
    : Double -> Json
    = \(x : Double) ->
      \(JSON : Type) ->
      \ ( json
        : { array : List JSON -> JSON
          , bool : Bool -> JSON
          , null : JSON
          , number : Double -> JSON
          , object : List { mapKey : Text, mapValue : JSON } -> JSON
          , string : Text -> JSON
          }
        ) ->
        json.number x

let null
    : Json
    = \(JSON : Type) ->
      \ ( json
        : { array : List JSON -> JSON
          , bool : Bool -> JSON
          , null : JSON
          , number : Double -> JSON
          , object : List { mapKey : Text, mapValue : JSON } -> JSON
          , string : Text -> JSON
          }
        ) ->
        json.null

let array
    : List Json -> Json
    = \(x : List Json) ->
      \(JSON : Type) ->
      \ ( json
        : { array : List JSON -> JSON
          , bool : Bool -> JSON
          , null : JSON
          , number : Double -> JSON
          , object : List { mapKey : Text, mapValue : JSON } -> JSON
          , string : Text -> JSON
          }
        ) ->
        json.array (map Json JSON (\(j : Json) -> j JSON json) x)

let object
    : List { mapKey : Text, mapValue : Json } -> Json
    = \(x : List { mapKey : Text, mapValue : Json }) ->
      \(JSON : Type) ->
      \ ( json
        : { array : List JSON -> JSON
          , bool : Bool -> JSON
          , null : JSON
          , number : Double -> JSON
          , object : List { mapKey : Text, mapValue : JSON } -> JSON
          , string : Text -> JSON
          }
        ) ->
        json.object
          ( map
              { mapKey : Text, mapValue : Json }
              { mapKey : Text, mapValue : JSON }
              ( \(kv : { mapKey : Text, mapValue : Json }) ->
                  { mapKey = kv.mapKey, mapValue = kv.mapValue JSON json }
              )
              x
          )

let strings
    : List Text -> Json
    = \(xs : List Text) -> array (map Text Json string xs)

in  { Type = Json, string, bool, number, null, array, object, strings, map }
