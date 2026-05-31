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
        # Drop-in overlay. The network resolver is the only build target; for a
        # fully offline binary, override the feature list:
        #   pkgs.email-privacy-cleaner.override { cargoFeatures = [ ]; }
        # Uses the consumer's own Rust toolchain so the overlay carries no
        # dependency on rust-overlay being applied downstream.
        overlays.default = final: prev: {
          email-privacy-cleaner = final.callPackage ./nix/package.nix {
            craneLib = crane.mkLib final;
            src = ./.;
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

          # Shared crane arguments so the checks and the dependency cache all
          # agree. `--all-features` builds the network resolver (the shipped
          # target), so the cached deps cover ureq/rustls for every check.
          commonArgs = {
            inherit src;
            pname = "email-privacy-cleaner";
            version = (lib.importTOML ./Cargo.toml).package.version;
            strictDeps = true;
            cargoExtraArgs = "--all-features";
          };
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;

          # Network resolver is the only target; `.override { cargoFeatures = [ ]; }`
          # yields a fully offline binary.
          email-privacy-cleaner = pkgs.callPackage ./nix/package.nix {
            inherit craneLib src;
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

          # `nix flake check` gates the package on the same quality bar as CI.
          checks = {
            inherit email-privacy-cleaner;

            # Full unit + integration + milter-protocol test suite, exercising
            # the network feature (the shipped target).
            tests = craneLib.cargoTest (commonArgs // { inherit cargoArtifacts; });

            # Lint all targets; warnings are errors. (Features come from
            # commonArgs.cargoExtraArgs.)
            clippy = craneLib.cargoClippy (
              commonArgs
              // {
                inherit cargoArtifacts;
                cargoClippyExtraArgs = "--all-targets -- --deny warnings";
              }
            );

            # Formatting.
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
