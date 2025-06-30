# Running tests

Run tests with (they are very slow):

```bash
cargo test -p minnow-core --release -- --test-threads 1
```

To use the fake proof system:

```bash
cargo test -p minnow-core --features fake
```
