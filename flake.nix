{
  description = "Revvault — age-encrypted secret vault with CLI and Tauri desktop app";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
        };

        # Tauri system dependencies (Linux/WSL)
        tauriDeps = with pkgs; [
          pkg-config
          openssl
          glib
          gtk3
          libsoup_3
          webkitgtk_4_1
          librsvg
          libappindicator-gtk3
        ];

        # Mesa drivers for EGL/GL (needed for WebKitGTK rendering)
        mesaDrivers = pkgs.mesa.drivers;

        # All native build inputs
        nativeBuildInputs = with pkgs; [
          rustToolchain
          cargo-tauri
          nodejs_22
          nodePackages.pnpm
        ] ++ tauriDeps;

      in {
        devShells.default = pkgs.mkShell {
          inherit nativeBuildInputs;

          buildInputs = with pkgs; [
            # Dev tools
            cargo-watch
            cargo-nextest
          ];

          shellHook = ''
            echo "revvault dev shell ready ($(rustc --version))"
            echo "  cargo build --workspace    # build all crates"
            echo "  cargo tauri dev            # launch Tauri app"
            echo "  cargo nextest run          # run tests"
          '';

          # Tauri needs these at runtime.
          # mesaDrivers provides libEGL_mesa.so.0 (needed by libglvnd) and
          # DRI drivers (d3d12 for WSLg, llvmpipe for software fallback).
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath (tauriDeps ++ [ mesaDrivers ]);
          LIBGL_DRIVERS_PATH = "${mesaDrivers}/lib/dri";

          # For openssl-sys
          OPENSSL_DIR = "${pkgs.openssl.dev}";
          OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
          OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";
        };
      });
}
