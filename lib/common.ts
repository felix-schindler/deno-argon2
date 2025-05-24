/**
 * This module contains types to configure argon2 and hashing operations.
 * @module
 */

/** Represents the minimum size required for the salt used in hashing operations. It ensures that the salt is sufficiently large to provide adequate security. */
export const MIN_SALT_SIZE = 8;

/**
 * Available Argon2 variants
 * Argon2i: Optimized to resist GPU cracking attacks, best for password hashing.
 * Argon2d: Provides better resistance against side-channel attacks.
 * Argon2id: A hybrid version combining Argon2i and Argon2d, offering balanced security.
 */
export enum Variant {
	Argon2i = "argon2i",
	Argon2d = "argon2d",
	Argon2id = "argon2id",
}

/**
 * Available Argon2 versions. Different versions may have different internal implementations and performance characteristics.
 */
export enum Version {
	V10 = "16",
	V13 = "19",
}

/**
 * Options required to configure a hashing operation using the Argon2 algorithm. This allows you to customize the security and performance characteristics of the hash.
 * salt: Uint8Array: The salt value used in the hashing operation. It must be at least MIN_SALT_SIZE bytes long to ensure security.
 * secret: Uint8Array: A secret key or value that can be combined with the data during the hashing operation for additional security.
 * data: T: The data to be hashed. The type T allows flexibility in specifying what kind of data can be hashed.
 * variant: Variant: Specifies the variant of Argon2 to use for hashing. It must be one of the values from the Variant enumeration.
 * version: Version: Specifies the version of Argon2 to use. It must be one of the values from the Version enumeration.
 * memoryCost: number: Specifies the amount of memory (in kilobytes) that the hashing algorithm should use. Higher values increase security but require more resources.
 * timeCost: number: Specifies the number of iterations (or time cost) the hashing algorithm should perform. Higher values increase the computation time, enhancing security.
 * lanes: number: The number of parallel lanes (or threads) used in the hashing operation. This allows for fine-tuning of performance and security.
 * hashLength: number: Specifies the desired length of the resulting hash (in bytes).
 */
// deno-lint-ignore ban-types
export interface HashOptions<T extends {} = {}> {
	salt: Uint8Array;
	secret: Uint8Array;
	data: T;
	variant: Variant;
	version: Version;
	memoryCost: number;
	timeCost: number;
	lanes: number;
	hashLength: number;
}

/**
 * Returns the current version of the library.
 */
export function version(): string {
	return "3.0.0-alpha.4";
}
