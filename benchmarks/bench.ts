import { hash, Variant, verify } from "@felix/argon2";

const password =
	"2gnF!WAcyhp#kB@tcYQa2$A%P64jEmXY!@8n2GSH$GggfgGfP*qH!EWwDaB%5mdB6pW2fK!KD@YNjvqwREfRCCAPc54c5@Sk";
const hashed =
	"$argon2i$v=19$m=4096,t=3,p=1$i8Pd309cCOP75oN8vz8FHA$qUk1NgsxOmz3nWc54jyuOnr+3hHbZz3k0Sb13id7Ai8";

Deno.bench({
	name: "hash argon2i",
	group: "hashing",
	baseline: true,
	async fn() {
		await hash(password);
	},
});

Deno.bench({
	name: "hash argon2d",
	group: "hashing",
	async fn() {
		await hash(password, { variant: Variant.Argon2d });
	},
});

Deno.bench({
	name: "hash argon2id",
	group: "hashing",
	async fn() {
		await hash(password, { variant: Variant.Argon2id });
	},
});

Deno.bench({
	name: "hash with given salt",
	group: "hashing-salt",
	baseline: true,
	async fn(b) {
		const salt = crypto.getRandomValues(
			new Uint8Array(Math.max(8, Math.random() * 32)),
		);
		b.start();
		await hash(password, { salt });
		b.end();
	},
});

Deno.bench({
	name: "hash with given data, secret and salt",
	group: "hashing",
	async fn(b) {
		const salt = crypto.getRandomValues(
			new Uint8Array(Math.max(8, Math.random() * 32)),
		);
		const secret = crypto.getRandomValues(
			new Uint8Array(Math.max(8, Math.random() * 32)),
		);
		const data = { hashedAt: Date.now() };
		b.start();
		await hash(password, { salt, secret, data });
		b.end();
	},
});

Deno.bench({
	name: "hash with memoryCost set at 1024",
	group: "hashing",
	async fn() {
		await hash(password, { memoryCost: 1024 });
	},
});

Deno.bench({
	name: "hash with timeCost set at 10",
	group: "hashing",
	async fn() {
		await hash(password, { timeCost: 6 });
	},
});

Deno.bench({
	name: "verify",
	group: "verifying",
	baseline: true,
	async fn() {
		await verify(hashed, password);
	},
});
