{
  description = "email-privacy-cleaner — offline email privacy sanitizer library + milter daemon for Stalwart";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    crane.url = "github:ipetkov/crane";

    flake-utils.url = "github:numtide/flake-utils";

    # Pin a reproducible Rust toolchain that honours the crate's MSRV.
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
      # System-independent outputs.
      systemIndependent = {
        # Drop-in overlay: `pkgs.email-privacy-cleaner` (offline build) and
        # `pkgs.email-privacy-cleaner-network` (with the opt-in resolver).
        # Uses the consumer's own Rust toolchain so the overlay carries no
        # dependency on rust-overlay being applied downstream.
        overlays.default = final: prev: {
          email-privacy-cleaner = final.callPackage ./nix/package.nix {
            craneLib = crane.mkLib final;
            src = ./.;
          };
          email-privacy-cleaner-network = final.callPackage ./nix/package.nix {
            craneLib = crane.mkLib final;
            src = ./.;
            cargoFeatures = [ "network" ];
          };
        };

        # NixOS module + the overlay it relies on.
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

          # Pinned stable toolchain wired into crane. The `default` profile
          # bundles clippy + rustfmt, which the `clippy`/`fmt` checks need.
          rustToolchain = pkgs.rust-bin.stable.latest.default;
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

          src = ./.;

          # Shared crane arguments so the package, the checks and the
          # dependency cache all agree.
          commonArgs = {
            inherit src;
            pname = "email-privacy-cleaner";
            version = (lib.importTOML ./Cargo.toml).package.version;
            strictDeps = true;
          };
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;

          callPackage = pkgs.callPackage;
          mkPkg =
            cargoFeatures:
            callPackage ./nix/package.nix {
              inherit craneLib src cargoFeatures;
            };

          email-privacy-cleaner = mkPkg [ ];
          email-privacy-cleaner-network = mkPkg [ "network" ];
        in
        {
          packages = {
            default = email-privacy-cleaner;
            inherit email-privacy-cleaner email-privacy-cleaner-network;
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

          # `nix flake check` gates the package on the same quality bar as CI.
          checks = {
            inherit email-privacy-cleaner email-privacy-cleaner-network;

            # Full unit + integration + milter-protocol test suite.
            tests = craneLib.cargoTest (commonArgs // { inherit cargoArtifacts; });

            # Lint with all targets/features; warnings are errors.
            clippy = craneLib.cargoClippy (
              commonArgs
              // {
                inherit cargoArtifacts;
                cargoClippyExtraArgs = "--all-targets --all-features -- --deny warnings";
              }
            );

            # Formatting.
            fmt = craneLib.cargoFmt { inherit src; };
          }
          # The NixOS module evaluates and the service builds (Linux only).
          // lib.optionalAttrs pkgs.stdenv.isLinux {
            nixos-module =
              (nixpkgs.lib.nixosSystem {
                inherit system;
                modules = [
                  self.nixosModules.default
                  (
                    { ... }:
                    {
                      boot.loader.grub.enable = false;
                      fileSystems."/".device = "nodev";
                      system.stateVersion = "24.11";
                      services.email-privacy-milter = {
                        enable = true;
                        settings.mode = "report-only";
                      };
                    }
                  )
                ];
              }).config.system.build.toplevel;
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
