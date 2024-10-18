import { argon2, Command } from "../deps.ts";

import { readStdin } from "../util.ts";

export const verify = new Command()
	.version(argon2.version())
	.description("Hash a new password or verify an already existing one.")
	.option("-H, --hash <arg:string>", "", { required: true })
	.option("-S, --secret <arg:string>", "")
	.action(async (options) => {
		const password = await readStdin();
		let secret: Uint8Array | undefined = undefined;
		if (options.secret) {
			const encoder = new TextEncoder();
			secret = encoder.encode(options.secret);
		}

		console.log(
			await argon2.verify(
				options.hash,
				password,
				secret,
			),
		);
	});
