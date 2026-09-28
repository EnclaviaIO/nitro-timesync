{
  description = "Keep an AWS Nitro Enclave's wall clock on the Nitro hypervisor time from /dev/nsm attestation documents";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        # Package, binary and output names all follow this. Keep it in sync
        # with `name` in Cargo.toml.
        name = "nitro-timesync";

        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        rustVersion = "1.88.0";

        craneLib = (crane.mkLib pkgs).overrideToolchain (p:
          p.rust-bin.stable.${rustVersion}.default);

        src = craneLib.cleanCargoSource ./.;
        inherit (craneLib.crateNameFromCargoToml { inherit src; }) version;

        commonArgs = {
          inherit src version;
          pname = name;
          strictDeps = true;
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # Native (glibc) build, for development and for hosts that run the
        # binary from a Nix store path.
        native = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          doCheck = false;
        });

        # Fully static musl build: the form an enclave image usually wants,
        # since it drags no shared-library closure into the measured image.
        # The crate has no C dependencies, so only the linker comes from
        # the musl toolchain.
        muslTarget = "${pkgs.stdenv.hostPlatform.parsed.cpu.name}-unknown-linux-musl";
        muslTargetEnv = pkgs.lib.toUpper (builtins.replaceStrings [ "-" ] [ "_" ] muslTarget);
        muslCc = pkgs.pkgsStatic.stdenv.cc;
        craneLibMusl = (crane.mkLib pkgs).overrideToolchain (p:
          p.rust-bin.stable.${rustVersion}.default.override {
            targets = [ muslTarget ];
          });
        muslArgs = commonArgs // {
          CARGO_BUILD_TARGET = muslTarget;
          "CARGO_TARGET_${muslTargetEnv}_LINKER" = "${muslCc}/bin/${muslCc.targetPrefix}cc";
        };
        static = craneLibMusl.buildPackage (muslArgs // {
          cargoArtifacts = craneLibMusl.buildDepsOnly muslArgs;
          doCheck = false;
        });
      in
      {
        packages = {
          ${name} = native;
          "${name}-static" = static;
          default = static;
        };

        checks = {
          "${name}-static" = static;
          "${name}-test" = craneLib.cargoTest (commonArgs // { inherit cargoArtifacts; });
          "${name}-clippy" = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- -D warnings";
          });
          "${name}-fmt" = craneLib.cargoFmt { inherit src; pname = name; inherit version; };
        };

        devShells.default = craneLib.devShell {
          checks = self.checks.${system};
        };
      });
}
