import { hash, Variant, Version } from "@felix/argon2";

const salt = crypto.getRandomValues(
	new Uint8Array(20),
);

const encoder = new TextEncoder();
const secret = encoder.encode("my-super-secret");

console.log(
	await hash("this-could_be/yourP4ssword", {
		salt,
		secret,
		variant: Variant.Argon2id,
		version: Version.V13,
		memoryCost: 8192,
		timeCost: 10,
		lanes: 4,
		hashLength: 32,
		data: {
			hashedAt: Date.now(),
			requestId: "a00d22c0-4681-4351-8c8f-6f02a42dd941",
		},
	}),
);
