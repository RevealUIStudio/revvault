{
  description = "Revault — age-encrypted secret vault with CLI and Tauri desktop app";

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
            echo "revault dev shell ready ($(rustc --version))"
            echo "  cargo build --workspace    # build all crates"
            echo "  cargo tauri dev            # launch Tauri app"
            echo "  cargo nextest run          # run tests"
          '';

          # Tauri needs these at runtime
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath tauriDeps;

          # For openssl-sys
          OPENSSL_DIR = "${pkgs.openssl.dev}";
          OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
          OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";
        };
      });
}
