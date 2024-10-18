import { assert, assertEquals, assertFalse, assertRejects } from "@std/assert";

import { hash, Variant, verify, Version } from "@felix/argon2";

const salt = crypto.getRandomValues(new Uint8Array(8));
const password =
	"2gnF!WAcyhp#kB@tcYQa2$A%P64jEmXY!@8n2GSH$GggfgGfP*qH!EWwDaB%5mdB6pW2fK!KD@YNjvqwREfRCCAPc54c5@Sk";
const hashed =
	"$argon2i$v=19$m=4096,t=3,p=1$i8Pd309cCOP75oN8vz8FHA$qUk1NgsxOmz3nWc54jyuOnr+3hHbZz3k0Sb13id7Ai8";

await hash("");

Deno.test({
	name: "hashing a password omitting the salt",
	async fn() {
		const hashed = await hash(password);

		assert(hashed);
		assertEquals(typeof hashed, "string");
	},
});

Deno.test({
	name: "hashing a password specifying the salt",
	async fn() {
		const hashed1 = await hash(password, { salt });
		const hashed2 = await hash(password, { salt });
		assertEquals(hashed1, hashed2);
	},
});

Deno.test({
	name: "failure when hashing a password with salt shorter then 8",
	fn() {
		const salt = crypto.getRandomValues(new Uint8Array(7));

		assertRejects(async () => {
			await hash(password, { salt });
		});
	},
});

Deno.test({
	name: "hashing a password specifying a secret",
	async fn() {
		const secret = crypto.getRandomValues(new Uint8Array(8));
		const hashed = await hash(password, { secret });

		assert(hashed);
	},
});

Deno.test({
	name: "hashing a password specifying a salt and a secret",
	async fn() {
		const secret = crypto.getRandomValues(new Uint8Array(8));
		const salt = crypto.getRandomValues(new Uint8Array(8));
		const hashed = await hash(password, { salt, secret });

		assert(hashed);
	},
});

Deno.test({
	name: "hashing a password specifying an attached set of data",
	async fn() {
		const hashed = await hash(password, {
			data: {
				hashedAt: Date.now(),
				requestId: "69e442b3-ea81-409a-89f0-1af1ba623d52",
			},
		});

		assert(hashed);
	},
});

Deno.test({
	name:
		"hashing a password specifying an attached set of data, a salt and a secret",
	async fn() {
		const secret = crypto.getRandomValues(new Uint8Array(8));
		const salt = crypto.getRandomValues(new Uint8Array(8));
		const hashed = await hash(password, {
			secret,
			salt,
			data: {
				hashedAt: Date.now(),
				requestId: "69e442b3-ea81-409a-89f0-1af1ba623d52",
			},
		});

		assert(hashed);
	},
});

Deno.test({
	name: "hashing a password specifying the memory cost",
	async fn() {
		const hashed = await hash(password, {
			memoryCost: 1024,
		});

		assert(/\$m=1024/.test(hashed));
	},
});

Deno.test({
	name: "hashing a password specifying the time cost",
	async fn() {
		const hashed = await hash(password, {
			timeCost: 6,
		});

		assert(/,t=6,/.test(hashed));
	},
});

Deno.test({
	name: "hashing a password specifying the variant",
	async fn() {
		const hashed = await hash(password, {
			variant: Variant.Argon2id,
		});

		assert(/^\$argon2id/.test(hashed));
	},
});

Deno.test({
	name: "hashing a password specifying the version",
	async fn() {
		const hashed = await hash(password, {
			version: Version.V10,
		});

		assert(/\$v=16/.test(hashed));
	},
});

Deno.test({
	name: "password verification",
	async fn() {
		const resultTrue = await verify(hashed, password);
		const resultFalse = await verify(hashed, "fail");

		assertEquals(resultTrue, true);
		assertEquals(resultFalse, false);
	},
});

Deno.test({
	name: "password verification with salt",
	async fn() {
		const hashed1 = await hash(password, { salt });
		assert(await verify(hashed1, password));
		const hashed2 = await hash("thiscouldbeanotherpassword", { salt });
		assertEquals(await verify(hashed2, password), false);
	},
});

Deno.test({
	name: "password verification with secret",
	async fn() {
		const encoder = new TextEncoder();
		const secret = encoder.encode("this-is-a-GEHEIMNIS");
		const hashed = await hash(password, { secret });

		assert(await verify(hashed, password, secret));
		assertFalse(
			await verify(hashed, password, encoder.encode("another secret")),
		);
		assertFalse(await verify(hashed, password, salt));
	},
});

Deno.test({
	name: "password verification with additional data",
	async fn() {
		const data = {
			hashedAt: Date.now(),
			requestId: crypto.randomUUID(),
		};

		const otherData = {
			hashedAt: Date.now(),
			requestId: crypto.randomUUID(),
		};

		const hashedWithData = await hash(password, { data });

		assert(await verify(hashedWithData, password, undefined, data));
		assertFalse(await verify(hashedWithData, password, undefined, otherData));
	},
});
