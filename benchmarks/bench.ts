import { Buffer } from "node:buffer";
import {
	hash as myHash,
	Variant,
	verify as myVerify,
	Version,
} from "@felix/argon2";
import { hash as hash2, verify as verify2 } from "jsr:@ts-rex/argon2";
import argon2id_3 from "jsr:@rabbit-company/argon2id";
import {
	hash as hash4,
	verify as verify4,
} from "jsr:@stdext/crypto@0.0.6/hash";
import { hash as hash5 } from "jsr:@denosaurs/argontwo@0.2.0";
import { hash as npmHash, verify as npmVerify } from "npm:argon2";
import { hash as npmHash2, verify as npmVerify2 } from "npm:@node-rs/argon2";

const encoder = new TextEncoder();

const password =
	"2gnF!WAcyhp#kB@tcYQa2$A%P64jEmXY!@8n2GSH$GggfgGfP*qH!EWwDaB%5mdB6pW2fK!KD@YNjvqwREfRCCAPc54c5@Sk";
const encodedPassword = encoder.encode(password);

const salt: string = crypto.randomUUID();
const encodedSalt = encoder.encode(salt);
const bufferSalt = Buffer.from(salt);

const hashed =
	"$argon2id$v=19$m=19456,t=2,p=1$dX4UDfel7xLyNtWEkbhoO57lVIrtkaby$yH+LNxtH89sTAB0+PnuOjCIal6b6bzhqWAvB0H1Z56g";

// Default settings (as far as they are supported by the libraries)
// OWASP recommended configuration with t=2 and 19 MiB memory.
const hash_length = 32;
const lanes = 1;
const mem_cost = 19456;
const time_cost = 2;

Deno.bench({
	name: "jsr:@felix/argon2",
	group: "hashing",
	baseline: true,
	async fn() {
		await myHash(password, {
			variant: Variant.Argon2id,
			version: Version.V13,
			salt: encodedSalt,
			memoryCost: mem_cost,
			timeCost: time_cost,
			lanes: lanes,
			hashLength: hash_length,
		});
	},
});

Deno.bench({
	name: "jsr:@ts-rex/argon2",
	group: "hashing",
	fn() {
		hash2(password);
	},
});

Deno.bench({
	name: "jsr:@rabbit-company/argon2id",
	group: "hashing",
	async fn() {
		await argon2id_3.hash(
			password,
			salt,
			lanes,
			mem_cost,
			time_cost,
			hash_length,
		);
	},
});

Deno.bench({
	name: "jsr:@stdext/crypto",
	group: "hashing",
	fn() {
		hash4({ name: "argon2", algorithm: "argon2id" }, password);
	},
});

Deno.bench({
	name: "jsr:@denosaurs/argontwo",
	group: "hashing",
	fn() {
		hash5(encodedPassword, encodedSalt, {
			algorithm: "Argon2id",
			version: 0x13,
			outputLength: hash_length,
			mCost: mem_cost,
			tCost: time_cost,
			pCost: lanes,
		});
	},
});

Deno.bench({
	name: "npm:argon2",
	group: "hashing",
	async fn() {
		await npmHash(password, {
			hashLength: hash_length,
			timeCost: time_cost,
			memoryCost: mem_cost,
			parallelism: lanes,
			type: 2,
			version: 19,
			salt: bufferSalt,
		});
	},
});

Deno.bench({
	name: "npm:@node-rs/argon2",
	group: "hashing",
	async fn() {
		await npmHash2(password, {
			memoryCost: mem_cost,
			timeCost: time_cost,
			outputLen: hash_length,
			parallelism: lanes,
			algorithm: 2,
			version: 1,
			salt: encodedSalt,
		});
	},
});

Deno.bench({
	name: "jsr:@felix/argon2",
	group: "verifying",
	baseline: true,
	async fn() {
		await myVerify(hashed, password);
	},
});

Deno.bench({
	name: "jsr:@ts-rex/argon2",
	group: "verifying",
	fn() {
		verify2(password, hashed);
	},
});

Deno.bench({
	name: "jsr:@rabbit-company/argon2id",
	group: "verifying",
	async fn() {
		await argon2id_3.verify(hashed, password);
	},
});

Deno.bench({
	name: "jsr:@stdext/crypto",
	group: "verifying",
	fn() {
		verify4("argon2", password, hashed);
	},
});

Deno.bench({
	name: "npm:argon2",
	group: "verifying",
	baseline: true,
	async fn() {
		await npmVerify(hashed, password);
	},
});

Deno.bench({
	name: "npm:@node-rs/argon2",
	group: "verifying",
	async fn() {
		await npmVerify2(hashed, password);
	},
});
