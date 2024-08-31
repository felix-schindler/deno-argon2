import { assert } from "@std/assert";

import type { Variant, Version } from "./common.ts";

/**
 * Defines the options for asserting that a password string is in the expected Argon2 encoded format. This interface allows specifying the Argon2 parameters used to validate the format of the password.
 */
interface AssertArgon2EncodedOptions {
	variant: Variant;
	version: Version;
	memoryCost: number;
	timeCost: number;
	lanes: number;
}

/**
 * Asserts that a given password string matches the expected Argon2 encoded format. This function uses a regular expression to validate the format based on the provided options, such as variant, version, memory cost, time cost, and lanes.
 * @param password The password string that is expected to be in Argon2 encoded format. If the string does not match the expected format, an assertion error is thrown.
 * @param [options={}] Optional settings to specify the expected Argon2 parameters. If not provided, default patterns are used to validate the format.
 * @throws {AssertionError} - Throws an assertion error if the password does not match the expected Argon2 encoded format.
 * @example
 * assertArgon2Encoded("$argon2id$v=19$m=65536,t=3,p=2$...", { variant: Variant.Argon2id, version: Version.V13 });
 */
export function assertArgon2Encoded(
	password: string,
	options: Partial<AssertArgon2EncodedOptions> = {},
): asserts password {
	const variant = options.variant ? options.variant : "argon2(i|d|id)";

	const version = options.version ? options.version : "(16|19)";

	const memoryCost = options.memoryCost ? options.memoryCost : "([0-9])+";

	const timeCost = options.timeCost ? options.timeCost : "([0-9])+";

	const lanes = options.lanes ? options.lanes : "([0-9])+";

	const rx = new RegExp(
		`^\\$${variant}\\$v=${version}\\$m=${memoryCost},t=${timeCost},p=${lanes}\\$.+$`,
	);

	assert(rx.test(password));
}
