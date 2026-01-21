{
  description = "Development environments for scut-drcom-client projects";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
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
      flake-utils,
      rust-overlay,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        # Rust toolchain
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "rust-analyzer"
            "rust-docs"
          ];
        };
      in
      {
        devShells = {
          # Rust development environment for scut-drcom-client-rs
          rust = pkgs.mkShell {
            buildInputs = with pkgs; [
              rustToolchain
              cargo

              # Required for pcap crate
              libpcap

              # Development tools
              pkg-config
              openssl
            ];

            shellHook = ''
              echo "Rust development environment for scut-drcom-client"
              echo "Rust version: $(rustc --version)"
              echo "Cargo version: $(cargo --version)"
            '';

            # Environment variables for building
            LIBPCAP_LIBDIR = "${pkgs.libpcap}/lib";
            PKG_CONFIG_PATH = "${pkgs.libpcap}/lib/pkgconfig";
          };

          # C development environment for scutclient
          c = pkgs.mkShell {
            buildInputs = with pkgs; [
              gcc
              cmake
              gnumake

              # Development tools
              gdb
              clang-tools # for clangd LSP
            ];

            shellHook = ''
              echo "C development environment for scutclient"
              echo "GCC version: $(gcc --version | head -n1)"
              echo "CMake version: $(cmake --version | head -n1)"
              echo ""
              echo "Navigate to ../scutclient to build the C project"
            '';
          };

          # Default shell (Rust)
          default = self.devShells.${system}.rust;
        };
      }
    );
}
