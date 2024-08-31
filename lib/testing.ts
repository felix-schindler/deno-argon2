import { assert } from "@std/assert";

import type { Variant, Version } from "./common.ts";

interface AssertArgon2EncodedOptions {
	variant: Variant;
	version: Version;
	memoryCost: number;
	timeCost: number;
	lanes: number;
}

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
