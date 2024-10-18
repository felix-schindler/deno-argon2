/**
 * This module contains the default `hash` and `verify` functions.
 * @module
 *
 * @example
 * ```ts
 * import { hash, verify } from "@felix/argon2";
 *
 * const hashedPassword = await hash("Geheim!123")
 * const isValid = await verify(hashedPassword, "Geheim!123")
 * ```
 */

import type { HashOptions } from "./common.ts";
import * as internal from "./internal.ts";

export * from "./common.ts";
export * from "./error.ts";

/**
 * Hash a string.
 * ```ts
 * console.log(await hash("test"));
 * // $argon2i$v=19$m=4096,t=3,p=1$rboCX6NY3Yh26iEzgKEmWA$daswToHMDCu94YHLk1a8Bhy9THuTJkA9fTA6QdCTqkc
 * ```
 *
 * The above command hash the password bla bla bla.
 *
 * You can tweak the time spent and the output hash adding custom options:
 * ```ts
 * let salt = crypto.getRandomValues(new Uint8Array(Math.max(8, Math.random() * 32)));
 * let secret = encode("my-super-secret")
 * console.log(await hash("test", {
 *   salt,
 *   secret,
 *   variant: Variant.Argon2id,
 *   version: Version.V13,
 *   memoryCost: 8192,
 *   timeCost: 10,
 *   lanes: 4,
 *   data: {
 *     hashedAt: Date.now(),
 *     requestId: "a00d22c0-4681-4351-8c8f-6f02a42dd941"
 *   }
 * }));
 *
 * // $argon2id$v=19$m=8192,t=10,p=4$HjLMjlAq6MY$UU9Xv8JTZy01Tlfr1rBF0Ql7quTHdwoQOjDwu5A9AOE
 * ```
 *
 * @param password A String value we want to hash.
 * @param options.salt A Uint8Array of minimum size of 8 used as salt.
 * @param options.secret Used for keyed hashing. This allows a secret key to be input at hashing time (from some external location) and be folded into the value of the hash.
 * @param options.data Used to fold any additional data into the hash value. Functionally, this behaves almost exactly like the secret or salt parameters; the data parameter is folding into the value of the hash.
 * @param options.variant One of the three Argon2 variants: `argon2i`, `argon2d` or `argon2id`. **Default**: "argon2i"
 * @param options.version The Argon2 version: `16` or `19`. **Default**: "16"
 * @param options.memoryCost Defines the memory usage, given in kibibytes. **Default**: 4096
 * @param options.timeCost The amount of computation realized and therefore the execution time, given in number of iterations. **Default**: 3
 * @returns A promise that resolves to the resulting hash encoded as a string.
 * @throws Throws an `Argon2Error` if the input password is not a string, the salt is too short, or if a native error occurs during hashing.
 */
export function hash(
	password: string,
	options: Partial<HashOptions> = {},
): Promise<string> {
	return internal.hash(password, options);
}

/**
 * Verify a password against a previously hashed value.
 * @param hash - The Argon2 hash that the password is being compared against. This must be a valid hash string.
 * @param password - The password to be verified against the hash. This must be a string.
 * @param secret - An optional secret string that was used during hashing. If provided, the secret must match the one used during hashing; otherwise, the verification fails.
 * @returns A promise that resolves to `true` if the password matches the hash, or `false` otherwise.
 * @throws Throws an `Argon2Error` if a native error occurs during the verification process.
 */
export function verify(
	hash: string,
	password: string,
	secret?: Uint8Array,
): Promise<boolean> {
	return internal.verify(hash, password, secret);
}
