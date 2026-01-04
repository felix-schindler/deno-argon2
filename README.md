# Argon2 for Deno

This repository is a continuation of
[fdionisi/deno-argon2](https://github.com/fdionisi/deno-argon2) which was no
longer actively maintained.

Fastest [Argon2](https://github.com/P-H-C/phc-winner-argon2) hashing library for
[Deno](https://deno.com). It uses
[argon2](https://github.com/RustCrypto/password-hashes/tree/master/argon2) via
[Deno FFI](https://docs.deno.com/runtime/reference/deno_namespace_apis/#ffi)
which requires Deno v1.30.0 or higher.

## Benchmarks

See [benchmarks/bench.ts](benchmarks/bench.ts) for more details. OWASP
recommended configuration with t=2 and 19 MiB memory (as far as supported by
library).

```
CPU | Apple M2 Pro
Runtime | Deno 2.6.3 (aarch64-apple-darwin)

file://[redacted]/deno-argon2/benchmarks/bench.ts

| benchmark                      | time/iter (avg) |        iter/s |      (min … max)      |      p75 |      p99 |     p995 |
| ------------------------------ | --------------- | ------------- | --------------------- | -------- | -------- | -------- |

group hashing
| jsr:@felix/argon2              |         13.5 ms |          74.1 | ( 12.5 ms …  28.7 ms) |  13.2 ms |  28.7 ms |  28.7 ms |
| jsr:@ts-rex/argon2             |         43.4 ms |          23.0 | ( 42.8 ms …  44.7 ms) |  43.5 ms |  44.7 ms |  44.7 ms |
| jsr:@rabbit-company/argon2id   |         42.7 ms |          23.4 | ( 41.4 ms …  46.1 ms) |  43.3 ms |  46.1 ms |  46.1 ms |
| jsr:@stdext/crypto             |         39.0 ms |          25.6 | ( 37.8 ms …  41.1 ms) |  39.4 ms |  41.1 ms |  41.1 ms |
| jsr:@denosaurs/argontwo        |         44.0 ms |          22.7 | ( 42.9 ms …  46.2 ms) |  44.8 ms |  46.2 ms |  46.2 ms |
| npm:argon2                     |         19.8 ms |          50.4 | ( 18.0 ms …  21.3 ms) |  20.4 ms |  21.3 ms |  21.3 ms |
| npm:@node-rs/argon2            |         14.5 ms |          68.9 | ( 13.2 ms …  19.1 ms) |  14.9 ms |  19.1 ms |  19.1 ms |

summary
  jsr:@felix/argon2
     1.08x faster than npm:@node-rs/argon2
     1.47x faster than npm:argon2
     2.89x faster than jsr:@stdext/crypto
     3.17x faster than jsr:@rabbit-company/argon2id
     3.22x faster than jsr:@ts-rex/argon2
     3.27x faster than jsr:@denosaurs/argontwo

group verifying
| jsr:@felix/argon2              |         13.4 ms |          74.8 | ( 12.6 ms …  14.5 ms) |  13.9 ms |  14.5 ms |  14.5 ms |
| jsr:@ts-rex/argon2             |         43.2 ms |          23.2 | ( 42.2 ms …  45.6 ms) |  43.7 ms |  45.6 ms |  45.6 ms |
| jsr:@rabbit-company/argon2id   |         42.1 ms |          23.7 | ( 41.1 ms …  45.6 ms) |  42.6 ms |  45.6 ms |  45.6 ms |
| jsr:@stdext/crypto             |         37.8 ms |          26.5 | ( 37.5 ms …  39.5 ms) |  37.7 ms |  39.5 ms |  39.5 ms |
| npm:argon2                     |         18.0 ms |          55.5 | ( 17.8 ms …  19.7 ms) |  18.0 ms |  19.7 ms |  19.7 ms |
| npm:@node-rs/argon2            |         17.4 ms |          57.5 | ( 13.1 ms …  53.5 ms) |  16.9 ms |  53.5 ms |  53.5 ms |

summary
  jsr:@felix/argon2
     1.30x faster than npm:@node-rs/argon2
     1.35x faster than npm:argon2
     2.83x faster than jsr:@stdext/crypto
     3.15x faster than jsr:@rabbit-company/argon2id
     3.23x faster than jsr:@ts-rex/argon2
```

## API

```ts
hash(password: string, options?: HashOptions): Promise<string>
verify(hash: string, password: string, secret?: Uint8Array, additionalData?: unknown): Promise<boolean>
```

### Error handling

In case of an error, all methods of this library will throw an
[`Argon2Error`](lib/error.ts) type.

## Usage

### Library

```ts
import { assert } from "jsr:@std/assert";
import { hash, verify } from "jsr:@felix/argon2";

const hash = await hash("test");

assert(await verify(hash, "test"));
```

#### Testing

```ts
import { Variant } from "jsr:@felix/argon2";
import { assertArgon2Encoded } from "jsr:@felix/argon2/lib/testing";

Deno.test("User#password should be an argon2id variant password", async () => {
	assertArgon2Encoded(user.password, {
		variant: Variant.Argon2id,
	});
});
```

## Permissions

The library automatically downloads the static library. It requires
`--allow-read`, `--allow-write`, `--allow-net` and `--allow-ffi`.

<details>

    ```sh
    deno \
      --allow-read \
      --allow-write \
      --allow-net \
      --allow-ffi \
      mod.ts
    ```

</details>

## Examples

In the [`examples/`](examples/) folder there you can find some usage examples.

> To run examples you must `--allow-run` since dev environment builds and
> initialize the Rust crate.

_**Available examples**_

- [Hash](examples/hash.ts)
- [Verify](examples/verify.ts)
- [Hash and verify with options](examples/with-options.ts)

## Contributing

### Project structure

```sh
deno-argon2
  ├── lib/         # Core library
  ├── native/      # Native glue code
  ├── tests/       # TypeScript tests
  ├── benchmarks/  # TypeScript benchmarks
  └── examples/    # Development examples
```

## License

[MIT](LICENSE)
