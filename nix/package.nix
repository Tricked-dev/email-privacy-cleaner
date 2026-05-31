# Package definition for email-privacy-cleaner / email-privacy-milter.
#
# Imported by flake.nix with a `craneLib` already instantiated for the target
# system. Kept free of flake plumbing so it can also be `callPackage`-d from an
# overlay or a plain `import <nixpkgs> {}` checkout.
{
  lib,
  stdenv,
  craneLib,
  # Build-time only; removed from the runtime closure afterwards.
  removeReferencesTo,
  # Cargo feature flags to compile in. The default build is fully offline and
  # has no native runtime dependencies; "network" pulls in the SSRF-guarded
  # resolver (ureq + rustls/ring, still no OpenSSL).
  cargoFeatures ? [ ],
  # Source root (the repository). Passed in so the expression has no implicit
  # dependency on its own location.
  src,
}:

let
  cargoToml = lib.importTOML (src + "/Cargo.toml");
  inherit (cargoToml.package) version;

  featureArgs =
    lib.optionalString (cargoFeatures != [ ])
      "--no-default-features --features ${lib.concatStringsSep "," cargoFeatures}";

  # Arguments shared between the dependency-only build, the final build and the
  # check derivations so every step hits the same cargo artifact cache.
  commonArgs = {
    inherit src version;
    pname = "email-privacy-cleaner";
    strictDeps = true;

    cargoExtraArgs = featureArgs;

    # Library + two binaries; no C/system libraries at build or run time.
    nativeBuildInputs = [ ];
    buildInputs = [ ];

    # Reproducibility: don't let cargo embed host paths.
    CARGO_PROFILE_RELEASE_STRIP = "symbols";
  };

  # Build *only* the dependency crates once; reused by the package and checks.
  cargoArtifacts = craneLib.buildDepsOnly commonArgs;
in
craneLib.buildPackage (
  commonArgs
  // {
    inherit cargoArtifacts;

    doCheck = false; # tests run as a separate flake check, not in the build.

    nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ removeReferencesTo ];

    # Reference stripping: a release Rust binary can retain store-path strings
    # pointing at the source tree and the toolchain in its (now stripped) debug
    # sections / panic messages. Scrub them so they never enter the runtime
    # closure, keeping the deployed artifact minimal.
    postInstall = ''
      for bin in "$out"/bin/*; do
        remove-references-to \
          -t ${src} \
          -t ${stdenv.cc} \
          -t ${stdenv.cc.cc} \
          "$bin"
      done
    '';

    # Fail the build if the source tree or the compiler wrapper leak into the
    # runtime closure. (libgcc_s lives in a separate `cc.cc.lib` output and is a
    # legitimate dynamic dependency, so it is deliberately not listed here.)
    disallowedReferences = [
      src
      stdenv.cc
    ];

    meta = {
      description = cargoToml.package.description;
      homepage = cargoToml.package.repository;
      license = with lib.licenses; [
        mit
        asl20
      ];
      mainProgram = "email-privacy-milter";
      platforms = lib.platforms.unix;
    };
  }
)
