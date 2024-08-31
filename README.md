# Argon2 for Deno

This repository is a continuation of
[fdionisi/deno-argon2](https://github.com/fdionisi/deno-argon2) which was no
longer actively maintained.

[Argon2](https://github.com/P-H-C/phc-winner-argon2) hashing library for
[Deno](https://deno.land). It uses
[rust-argon2](https://github.com/sru-systems/rust-argon2) via
[Deno FFI](https://deno.land/manual@v1.30.0/runtime/ffi_api) which requires Deno
v1.30.0 or higher.

## Benchmarks

Benchmark measures performance against [x/bcrypt](https://deno.land/x/bcrypt).
See [`benchmarks/`](benchmarks/) folder for more details.

```
cpu: Apple M2 Pro
runtime: deno 1.45.5 (aarch64-apple-darwin)

file://[redacted]/deno-argon2/benchmarks/bench.ts
benchmark                                  time (avg)        iter/s             (min … max)       p75       p99      p995
------------------------------------------------------------------------------------------- -----------------------------

group hashing
hash argon2i                                5.46 ms/iter         183.1      (5.3 ms … 5.78 ms) 5.49 ms 5.74 ms 5.78 ms
hash argon2d                                5.38 ms/iter         185.8      (5.22 ms … 5.5 ms) 5.41 ms 5.49 ms 5.5 ms
hash argon2id                                5.4 ms/iter         185.3     (5.27 ms … 5.77 ms) 5.43 ms 5.74 ms 5.77 ms
hash with given data, secret and salt       5.46 ms/iter         183.1     (5.33 ms … 5.79 ms) 5.49 ms 5.7 ms 5.79 ms
hash with memoryCost set at 1024            1.34 ms/iter         743.6     (1.29 ms … 1.62 ms) 1.36 ms 1.46 ms 1.48 ms
hash with timeCost set at 10                10.7 ms/iter          93.5    (10.48 ms … 10.9 ms) 10.75 ms 10.9 ms 10.9 ms
hash with 16 lanes on sequential mode       5.66 ms/iter         176.7     (5.54 ms … 6.02 ms) 5.69 ms 6.02 ms 6.02 ms

group hashing-salt
hash with given salt                        5.55 ms/iter         180.3     (5.35 ms … 6.04 ms) 5.63 ms 5.99 ms 6.04 ms

group verifying
verify                                      5.52 ms/iter         181.2     (5.35 ms … 6.02 ms) 5.61 ms 5.92 ms 6.02 ms
```

## API

```ts
hash(password: string, options?: HashOptions): Promise<string>
verify(hash: string, password: string): Promise<boolean>
```

### Error handling

In case of an error, all methods of this library will throw an
[`Argon2Error`](lib/error.ts) type.

## Usage

### Library

```ts
import { assert } from "https://deno.land/std/testing/asserts.ts";
import { hash, verify } from "https://deno.land/x/argon2_ffi/mod.ts";

const hash = await hash("test");

assert(await verify(hash, "test"));
```

#### Testing

```ts
import { Variant } from "https://deno.land/x/argon2_ffi/mod.ts";
import { assertArgon2Encoded } from "https://deno.land/x/argon2_ffi/lib/testing.ts";

Deno.test("User#password should be an argon2id variant password", async () => {
	assertArgon2Encoded(user.password, {
		variant: Variant.Argon2id,
	});
});
```

### CLI

The library can be installed as a CLI tool via `deno install`.

<details>

<summary>Installation snippet</summary>

    ```sh
    deno install \
      -A \
      --unstable \
      argon2 https://deno.land/x/argon2_ffi/cli/argon2.ts
    ```

</details>

After install run `--help` to inspect all possible commands.

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
      --unstable \
      mod.ts
    ```

</details>

## Examples

In the [`examples/`](examples/) folder there you can find some usage examples.

> To run examples you must `--allow-run` since dev environment builds and
> initialize the Rust crate.

_**Available examples**_

- [Hash](examples/hash.ts)
- [Hash with options](examples/hash-with-options.ts)
- [Verify](examples/verify.ts)

## Contributing

### Project structure

```sh
deno-argon2
  ├── lib/         # Core library
  ├── native/      # Native glue code
  ├── cli/         # CLI wrapper
  ├── tests/       # TypeScript tests
  ├── benchmarks/  # TypeScript benchmarks
  └── examples/    # Development examples
```

## License

[MIT](LICENSE)
