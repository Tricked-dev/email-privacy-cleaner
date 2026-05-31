# NixOS module exposing the milter daemon as a hardened systemd service.
#
# Wired up by the flake's `nixosModules.default`, which also applies the
# overlay so `pkgs.email-privacy-cleaner` resolves. Enable with:
#
#   services.email-privacy-milter = {
#     enable = true;
#     listen = "127.0.0.1:11333";
#     settings = { mode = "enforce"; remove_pixels = true; };
#   };
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.email-privacy-milter;
  tomlFormat = pkgs.formats.toml { };

  # Resolve each rule pack to a store path. Plain paths pass through; an
  # `{ url; sha256; }` entry is prefetched at build time with `fetchurl` and
  # pinned by hash, so the daemon loads it offline from the store (the
  # per-message cleaning path never touches the network). Passed to the daemon
  # as `--rule-pack` args, so this composes with EITHER `settings` or
  # `configFile` — the packs merge on top of whatever `rule_packs` the config
  # already lists.
  resolvedRulePacks = map (
    p: if builtins.isAttrs p then pkgs.fetchurl { inherit (p) url sha256; } else p
  ) cfg.rulePacks;

  rulePackArgs = lib.concatMap (p: [
    "--rule-pack"
    (toString p)
  ]) resolvedRulePacks;

  # A config file is only passed when the user supplies one; otherwise the
  # daemon runs on its built-in defaults plus the --listen override.
  configPath =
    if cfg.configFile != null then
      cfg.configFile
    else if cfg.settings != { } then
      tomlFormat.generate "email-privacy-cleaner.toml" cfg.settings
    else
      null;

  configArgs = lib.optionals (configPath != null) [
    "--config"
    (toString configPath)
  ];

  # Lock socket-level networking to loopback when the daemon listens on a
  # loopback address (the common MTA-over-localhost case); otherwise leave it
  # open so a remote MTA can connect.
  listenHost = lib.head (lib.splitString ":" cfg.listen);
  isLoopback = builtins.elem listenHost [
    "127.0.0.1"
    "::1"
    "localhost"
  ];
in
{
  options.services.email-privacy-milter = {
    enable = lib.mkEnableOption "the email-privacy-cleaner milter daemon";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.email-privacy-cleaner;
      defaultText = lib.literalExpression "pkgs.email-privacy-cleaner";
      description = "The email-privacy-cleaner package providing email-privacy-milter.";
    };

    listen = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:11333";
      example = "127.0.0.1:11333";
      description = ''
        TCP `address:port` the milter listens on. Passed via `--listen`, so it
        also overrides any `listen` key in {option}`settings`/{option}`configFile`.
      '';
    };

    settings = lib.mkOption {
      type = tomlFormat.type;
      default = { };
      example = lib.literalExpression ''
        {
          mode = "enforce";
          remove_pixels = true;
          clean_query_params = true;
          extra_tracking_params = [ "my_custom_tracker" "mkt_*" ];
          # Exclusions (carve-outs that override the rule pack):
          keep_params = [ "ref" ];          # never strip these
          exclude_domains = [ "intranet.example" ]; # leave these hosts untouched
          disabled_providers = [ "amazon" ];        # switch off one provider
        }
      '';
      description = ''
        Declarative cleaner configuration, rendered to a TOML file and passed
        with `--config`. See `config.example.toml` in the repository for every
        key and its default. Ignored if {option}`configFile` is set.
      '';
    };

    configFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        Path to a pre-written TOML config file. Mutually exclusive with
        {option}`settings`; use this to manage the config out of band (e.g. via
        a secret-management tool).
      '';
    };

    rulePacks = lib.mkOption {
      type =
        with lib.types;
        listOf (
          either path (submodule {
            options = {
              url = lib.mkOption {
                type = str;
                description = "URL of a ClearURLs-format rule pack to prefetch at build time.";
              };
              sha256 = lib.mkOption {
                type = str;
                description = "Expected hash of the pack, as accepted by {function}`fetchurl`.";
              };
            };
          })
        );
      default = [ ];
      example = lib.literalExpression ''
        [
          # A pack already in the store / repo:
          ./my-extra-rules.json
          # Or prefetch the upstream ClearURLs data (pinned by hash) so it is
          # baked into the store and loaded fully offline at runtime:
          {
            url = "https://rules2.clearurls.xyz/data.min.json";
            sha256 = "sha256-AAAA...";
          }
        ]
      '';
      description = ''
        External ClearURLs-format rule packs to merge on top of the built-ins.
        Each entry is either a path, or an `{ url; sha256; }` attrset that is
        fetched with {function}`fetchurl` and pinned. The resolved store paths
        are passed to the daemon as `--rule-pack` arguments and merged on top of
        the `rule_packs` in {option}`settings`/{option}`configFile`, so this
        composes with both and needs no network access at runtime.

        > The upstream ClearURLs rules are copyleft (LGPL); only their
        > *parser* ships with this package. Prefetching the data here keeps your
        > build reproducible and offline.
      '';
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Open the milter's TCP port in the firewall. Usually unnecessary: the
        MTA normally connects over loopback.
      '';
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Extra command-line arguments appended to the daemon invocation.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = !(cfg.settings != { } && cfg.configFile != null);
        message = "services.email-privacy-milter: set either `settings` or `configFile`, not both.";
      }
    ];

    networking.firewall = lib.mkIf cfg.openFirewall (
      let
        port = lib.toInt (lib.last (lib.splitString ":" cfg.listen));
      in
      {
        allowedTCPPorts = [ port ];
      }
    );

    systemd.services.email-privacy-milter = {
      description = "Email privacy cleaner milter daemon";
      documentation = [ "https://github.com/tricked-dev/mail-milter" ];
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = lib.concatStringsSep " " (
          [
            (lib.getExe cfg.package)
            "--listen"
            cfg.listen
          ]
          ++ configArgs
          ++ rulePackArgs
          ++ cfg.extraArgs
        );

        Restart = "on-failure";
        RestartSec = "2s";

        # --- Privilege & identity ---
        DynamicUser = true;
        # The daemon is stateless; no StateDirectory required.

        # --- Sandboxing / hardening ---
        # Pre-queue milters are exposed to attacker-controlled message bodies,
        # so lock the service down aggressively. It needs nothing but a TCP
        # listening socket and read access to its (world-readable) config.
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        PrivateUsers = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        ProcSubset = "pid";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RemoveIPC = true;
        UMask = "0077";

        # Network: a TCP listener over IPv4/IPv6 only. The default build never
        # makes outbound connections; even with the `network` feature the
        # resolver is allowlist-only and SSRF-guarded.
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
        ];
        IPAddressAllow = lib.mkDefault (if isLoopback then "localhost" else "any");
        IPAddressDeny = lib.mkDefault "any";

        SystemCallFilter = [
          "@system-service"
          "~@privileged"
          "~@resources"
        ];
        SystemCallArchitectures = "native";
        SystemCallErrorNumber = "EPERM";

        CapabilityBoundingSet = "";
        AmbientCapabilities = "";

        # --- Resource ceilings (defence in depth atop the in-app limits) ---
        LimitNOFILE = 4096;
        MemoryMax = lib.mkDefault "512M";
        TasksMax = lib.mkDefault 64;
      };
    };
  };
}
