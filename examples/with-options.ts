import { hash, Variant, verify, Version } from "@felix/argon2";

const salt = crypto.getRandomValues(
	new Uint8Array(20),
);

const encoder = new TextEncoder();
const password = "this-could_be/yourP4ssword";
const secret = encoder.encode("my-super-secret");
const data = {
	hashedAt: Date.now(),
	requestId: crypto.randomUUID(),
};

const hashed = await hash(password, {
	salt,
	secret,
	variant: Variant.Argon2id,
	version: Version.V13,
	memoryCost: 8192,
	timeCost: 10,
	lanes: 4,
	hashLength: 32,
	data,
});

await verify(hashed, password, secret, data);
