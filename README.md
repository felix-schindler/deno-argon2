# Argon2 for Deno

This repository is a continuation of
[fdionisi/deno-argon2](https://github.com/fdionisi/deno-argon2) which was no
longer actively maintained.

Fastest [Argon2](https://github.com/P-H-C/phc-winner-argon2) hashing library for
[Deno](https://deno.com). It uses
[rust-argon2](https://github.com/sru-systems/rust-argon2) via
[Deno FFI](https://docs.deno.com/runtime/reference/deno_namespace_apis/#ffi)
which requires Deno v1.30.0 or higher.

## Benchmarks

See [benchmarks/bench.ts](benchmarks/bench.ts) for more details. OWASP
recommended configuration with t=2 and 19 MiB memory (as far as supported by
library).

```
CPU | Apple M2 Pro
Runtime | Deno 2.0.0 (aarch64-apple-darwin)

file://[redacted]/deno-argon2/benchmarks/bench.ts

benchmark                      time/iter (avg)        iter/s      (min … max)           p75      p99     p995
------------------------------ ----------------------------- --------------------- --------------------------

group hashing
jsr:@felix/argon2                      17.2 ms          58.2 ( 17.0 ms …  18.9 ms)  17.2 ms  18.9 ms  18.9 ms
jsr:@ts-rex/argon2                     44.7 ms          22.4 ( 44.6 ms …  45.6 ms)  44.8 ms  45.6 ms  45.6 ms
jsr:@rabbit-company/argon2id           45.3 ms          22.1 ( 42.4 ms …  49.0 ms)  46.6 ms  49.0 ms  49.0 ms
jsr:@stdext/crypto                     39.5 ms          25.3 ( 38.6 ms …  42.6 ms)  40.1 ms  42.6 ms  42.6 ms
jsr:@denosaurs/argontwo                45.4 ms          22.1 ( 43.5 ms …  50.6 ms)  47.1 ms  50.6 ms  50.6 ms
npm:argon2                             19.0 ms          52.8 ( 17.8 ms …  21.0 ms)  19.4 ms  21.0 ms  21.0 ms

summary
jsr:@felix/argon2
 1.10x faster than npm:argon2
 2.29x faster than jsr:@stdext/crypto
 2.60x faster than jsr:@ts-rex/argon2
 2.63x faster than jsr:@rabbit-company/argon2id
 2.64x faster than jsr:@denosaurs/argontwo

group verifying
jsr:@felix/argon2                      17.1 ms          58.5 ( 17.0 ms …  17.3 ms)  17.1 ms  17.3 ms  17.3 ms
jsr:@ts-rex/argon2                     45.4 ms          22.0 ( 44.5 ms …  48.2 ms)  46.2 ms  48.2 ms  48.2 ms
jsr:@rabbit-company/argon2id           43.3 ms          23.1 ( 42.3 ms …  47.3 ms)  43.1 ms  47.3 ms  47.3 ms
jsr:@stdext/crypto                     39.7 ms          25.2 ( 38.8 ms …  43.0 ms)  39.7 ms  43.0 ms  43.0 ms
npm:argon2                             19.1 ms          52.3 ( 18.3 ms …  24.2 ms)  18.9 ms  24.2 ms  24.2 ms

summary
jsr:@felix/argon2
 1.12x faster than npm:argon2
 2.32x faster than jsr:@stdext/crypto
 2.53x faster than jsr:@rabbit-company/argon2id
 2.65x faster than jsr:@ts-rex/argon2
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
