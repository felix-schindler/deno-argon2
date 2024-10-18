import type { Variant } from "../../lib/mod.ts";
import { argon2, Command } from "../deps.ts";
import { readStdin } from "../util.ts";

const encoder = new TextEncoder();

export const hash = new Command()
	.version(argon2.version())
	.description("Hash a new password or verify an already existing one.")
	.option("-s, --salt <arg:string>", "")
	.option("-S, --secret <arg:string>", "")
	.option("-m, --memory-cost <arg:number>", "")
	.option("-t, --time-cost <arg:number>", "")
	.option("-l, --lanes <arg:number>", "")
	.option("-v, --variant <arg:variant>", "")
	.option("-d, --data <arg:json>", "")
	.option("-H, --hash-length <arg:number>", "")
	.type("variant", ({
		name,
		value,
	}) => {
		switch (value) {
			case argon2.Variant.Argon2i:
			case argon2.Variant.Argon2d:
			case argon2.Variant.Argon2id: {
				return value;
			}
			// deno-lint-ignore no-empty
			case undefined: {}
			default: {
				throw new Error(
					`Option --${name} must be either "${argon2.Variant.Argon2i}", "${argon2.Variant.Argon2d}" or "${argon2.Variant.Argon2id}": ${value}`,
				);
			}
		}
	})
	.type("json", ({
		name,
		value,
	}) => {
		try {
			if (value !== undefined) {
				return JSON.parse(value);
			}
		} catch (_) {
			throw new Error(
				`Option --${name} must be a valid json object: ${value}`,
			);
		}
	})
	.action(async (options) => {
		const password = await readStdin();

		console.log(
			await argon2.hash(password, {
				salt: options.salt ? encoder.encode(options.salt) : undefined,
				secret: options.secret ? encoder.encode(options.secret) : undefined,
				memoryCost: options.memoryCost ? options.memoryCost : undefined,
				timeCost: options.timeCost ? options.timeCost : undefined,
				lanes: options.lanes ? options.lanes : undefined,
				variant: options.variant ? options.variant as Variant : undefined,
				data: options.data ? options.data : undefined,
				hashLength: options.hashLength ? options.hashLength : undefined,
			}),
		);
	});
