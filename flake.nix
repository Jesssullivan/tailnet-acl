{
  description = "Tailscale ACL management with Dhall";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.dhall
            pkgs.dhall-json
            pkgs.just
            pkgs.python3
          ];

          shellHook = ''
            echo "tailnet-acl dev shell"
            echo "  dhall:         $(dhall --version)"
            echo "  dhall-to-json: $(dhall-to-json --version)"
            echo "  just:          $(just --version)"
          '';
        };
      }
    );
}
