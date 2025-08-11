This is a proof-of-concept Monero blockchain data selector for proof-of-work purposes.

## Build

A C11-compatible compiler and `cmake` are required.

```
git clone https://github.com/tevador/bc_selector.git
cd bc_selector
mkdir build
cd build
cmake ..
make
```

## Usage

```
./bc_selector /path/to/monero/lmdb --height 3000000 --threads 8
```
