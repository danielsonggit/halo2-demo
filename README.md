# Halo2 ZK-SNARKs Learning Demo

[![Rust](https://img.shields.io/badge/rust-1.86.0-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A comprehensive learning project for the [Halo2](https://github.com/zcash/halo2) zero-knowledge proof library, covering complete implementations from basic chip design to advanced optimization techniques.

## Project Purpose

A Rust-based repository to document and experiment with Halo2 zero-knowledge proof circuits

## Project Structure

```
halo2-demo/
├── src/
│   ├── basic/                      # Basic chip design modules
│   │   ├── basic_chip.rs          # Single chip design (square sum)
│   │   ├── basic_middle.rs        # Optimized chip design (multi-gate)
│   │   ├── multi_chip_design.rs   # Modular multi-chip architecture
│   │   └── mod.rs
│   ├── lookup/                     # Lookup table modules
│   │   ├── table.rs               # Basic lookup table implementation
│   │   ├── rangecheck_lookup.rs   # Small range lookup verification
│   │   ├── large_range_analysis.rs # Large range value processing
│   │   └── mod.rs
│   ├── lib.rs
│   └── main.rs
├── images/                         # Circuit visualization output
├── rust-toolchain.toml            # Rust version lock
├── Cargo.toml                     # Project dependencies
└── README.md                      # Project documentation
```

## Quick Start

### Prerequisites

- Rust 1.86.0+ (version locked in project)
- Git

### Installation

```bash
# Clone the project
git clone <your-repo-url>
cd halo2-demo

# Build the project (Rust toolchain auto-configured)
cargo build --release

# Run tests
cargo test --release
```

## Testing

### Basic Function Tests

```bash
# Test basic chip design
cargo test test_square_sum_circuit --release

# Test optimized chip design
cargo test test_optimized_circuit --release

# Test multi-chip modular design
cargo test test_multi_chip_circuit --release
```

### Lookup Table Tests

```bash
# Test small range lookup
cargo test test_rangecheck_lookup --release

# Test bit decomposition approach
cargo test test_bit_decomposition_range_check --release

# Test binary constraint approach
cargo test test_binary_range_check --release
```

### Circuit Visualization

Enable `dev-graph` feature to generate circuit diagrams:

```bash
# Generate circuit visualization
cargo test --release --features dev-graph

# View generated images
ls images/
# basic_multi_chip.png
# multi_chip_design.png
# lookup.png
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
