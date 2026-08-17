# Package definition for email-privacy-cleaner / email-privacy-milter.
#
# Imported by flake.nix with a `craneLib` already instantiated for the target
# system. Kept free of flake plumbing so it can also be `callPackage`-d from an
# overlay or a plain `import <nixpkgs> {}` checkout.
{
  lib,
  stdenv,
  craneLib,
  removeReferencesTo,
  cargoFeatures ? [ "network" ],
  cargoArtifacts ? null,
  src,
}:

let
  cargoToml = lib.importTOML (src + "/Cargo.toml");
  inherit (cargoToml.package) version;

  featureArgs =
    "--no-default-features"
    + lib.optionalString (cargoFeatures != [ ]) " --features ${lib.concatStringsSep "," cargoFeatures}";

  commonArgs = {
    inherit src version;
    pname = "email-privacy-cleaner";
    strictDeps = true;
    cargoExtraArgs = featureArgs;
    nativeBuildInputs = [ ];
    buildInputs = [ ];
    CARGO_PROFILE_RELEASE_STRIP = "symbols";
  };

  resolvedCargoArtifacts =
    if cargoArtifacts == null then craneLib.buildDepsOnly commonArgs else cargoArtifacts;
in
craneLib.buildPackage (
  commonArgs
  // {
    cargoArtifacts = resolvedCargoArtifacts;
    doCheck = false;

    nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ removeReferencesTo ];

    postInstall = ''
      for bin in "$out"/bin/*; do
        remove-references-to \
          -t ${src} \
          -t ${stdenv.cc} \
          -t ${stdenv.cc.cc} \
          "$bin"
      done
    '';

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
