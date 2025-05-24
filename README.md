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
Runtime | Deno 2.3.3 (aarch64-apple-darwin)

file://[redacted]/deno-argon2/benchmarks/bench.ts

benchmark                      time/iter (avg)        iter/s      (min … max)           p75      p99     p995
------------------------------ ----------------------------- --------------------- --------------------------

group hashing
jsr:@felix/argon2                      13.8 ms          72.3 ( 13.2 ms …  16.1 ms)  14.0 ms  16.1 ms  16.1 ms
jsr:@ts-rex/argon2                     43.5 ms          23.0 ( 42.4 ms …  45.0 ms)  44.2 ms  45.0 ms  45.0 ms
jsr:@rabbit-company/argon2id           42.0 ms          23.8 ( 41.2 ms …  43.5 ms)  42.3 ms  43.5 ms  43.5 ms
jsr:@stdext/crypto                     38.6 ms          25.9 ( 37.7 ms …  39.4 ms)  39.3 ms  39.4 ms  39.4 ms
jsr:@denosaurs/argontwo                43.4 ms          23.1 ( 42.3 ms …  44.7 ms)  44.1 ms  44.7 ms  44.7 ms
npm:argon2                             19.3 ms          51.7 ( 18.4 ms …  21.1 ms)  19.7 ms  21.1 ms  21.1 ms
npm:@node-rs/argon2                    14.6 ms          68.5 ( 13.1 ms …  26.3 ms)  14.8 ms  26.3 ms  26.3 ms

summary
jsr:@felix/argon2
 1.05x faster than npm:@node-rs/argon2
 1.40x faster than npm:argon2
 2.79x faster than jsr:@stdext/crypto
 3.04x faster than jsr:@rabbit-company/argon2id
 3.14x faster than jsr:@denosaurs/argontwo
 3.15x faster than jsr:@ts-rex/argon2

group verifying
jsr:@felix/argon2                      14.8 ms          67.8 ( 13.4 ms …  16.4 ms)  15.2 ms  16.4 ms  16.4 ms
jsr:@ts-rex/argon2                     43.3 ms          23.1 ( 42.1 ms …  44.9 ms)  43.8 ms  44.9 ms  44.9 ms
jsr:@rabbit-company/argon2id           44.1 ms          22.7 ( 41.6 ms …  46.0 ms)  45.1 ms  46.0 ms  46.0 ms
jsr:@stdext/crypto                     39.1 ms          25.6 ( 38.0 ms …  41.3 ms)  39.5 ms  41.3 ms  41.3 ms
npm:argon2                             19.3 ms          51.8 ( 18.5 ms …  22.1 ms)  19.5 ms  22.1 ms  22.1 ms
npm:@node-rs/argon2                    13.6 ms          73.8 ( 13.1 ms …  15.7 ms)  13.8 ms  15.7 ms  15.7 ms

summary
jsr:@felix/argon2
 1.09x slower than npm:@node-rs/argon2
 1.31x faster than npm:argon2
 2.65x faster than jsr:@stdext/crypto
 2.94x faster than jsr:@ts-rex/argon2
 2.99x faster than jsr:@rabbit-company/argon2id
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
