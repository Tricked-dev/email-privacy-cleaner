{
  description = "email-privacy-cleaner — offline email privacy sanitizer library + milter daemon for Stalwart";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      flake-utils,
      rust-overlay,
    }:
    let
      systemIndependent = {
        overlays.default = final: prev: {
          email-privacy-cleaner = final.callPackage ./nix/package.nix {
            craneLib = crane.mkLib final;
            src = ./.;
          };
        };

        nixosModules.default = {
          imports = [ ./nix/module.nix ];
          nixpkgs.overlays = [ self.overlays.default ];
        };
        nixosModules.email-privacy-milter = self.nixosModules.default;
      };

      perSystem = flake-utils.lib.eachDefaultSystem (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };

          inherit (pkgs) lib;
          rustToolchain = pkgs.rust-bin.stable.latest.default;
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
          src = ./.;
          version = (lib.importTOML ./Cargo.toml).package.version;

          commonArgs = {
            inherit src version;
            pname = "email-privacy-cleaner";
            strictDeps = true;
            cargoExtraArgs = "--no-default-features --features network";
            CARGO_PROFILE_RELEASE_STRIP = "symbols";
          };

          cargoArtifacts = craneLib.buildDepsOnly commonArgs;

          email-privacy-cleaner = pkgs.callPackage ./nix/package.nix {
            inherit craneLib src cargoArtifacts;
          };
        in
        {
          packages = {
            default = email-privacy-cleaner;
            inherit email-privacy-cleaner;
          };

          apps = {
            default = flake-utils.lib.mkApp {
              drv = email-privacy-cleaner;
              name = "email-privacy-milter";
            };
            cli = flake-utils.lib.mkApp {
              drv = email-privacy-cleaner;
              name = "email-privacy-cleaner";
            };
            milter = flake-utils.lib.mkApp {
              drv = email-privacy-cleaner;
              name = "email-privacy-milter";
            };
          };

          checks = {
            default = email-privacy-cleaner;
            inherit email-privacy-cleaner;

            tests = craneLib.cargoTest (commonArgs // { inherit cargoArtifacts; });

            clippy = craneLib.cargoClippy (
              commonArgs
              // {
                inherit cargoArtifacts;
                cargoClippyExtraArgs = "--all-targets -- --deny warnings";
              }
            );

            fmt = craneLib.cargoFmt { inherit src; };
          };

          devShells.default = craneLib.devShell {
            checks = self.checks.${system};
            packages = with pkgs; [
              rust-analyzer
              cargo-audit
              cargo-edit
              nixfmt-rfc-style
            ];
          };

          formatter = pkgs.nixfmt-rfc-style;
        }
      );
    in
    systemIndependent // perSystem;
}
