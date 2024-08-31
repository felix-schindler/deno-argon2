import { type HashOptions, MIN_SALT_SIZE, version } from "./common.ts";
import { Argon2Error, Argon2ErrorType } from "./error.ts";
import { dlopen, type FetchOptions } from "./deps.ts";

const LOCAL = Deno.env.get("LOCAL");

function getLocalUrl(): string {
	const url = new URL("../target/release", import.meta.url);

	let uri = url.pathname;
	if (!uri.endsWith("/")) uri += "/";

	// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya#parameters
	if (Deno.build.os === "windows") {
		uri = uri.replace(/\//g, "\\");
		// Remove leading slash
		if (uri.startsWith("\\")) {
			uri = uri.slice(1);
		}
	}

	return uri;
}

const FETCH_OPTIONS: FetchOptions = {
	name: "deno_argon2",
	url: LOCAL
		? getLocalUrl()
		: `https://github.com/felix-schindler/deno-argon2/releases/download/v${version()}/`,
	cache: LOCAL ? "reloadAll" : "use",
};

const SYMBOLS = {
	hash: {
		parameters: ["buffer", "usize"],
		result: "pointer",
		nonblocking: true,
	},
	verify: {
		parameters: ["buffer", "usize"],
		result: "pointer",
		nonblocking: true,
	},
	free_buf: {
		parameters: ["pointer", "usize"],
		result: "void",
	},
} as const;

const lib = await dlopen(FETCH_OPTIONS, SYMBOLS);

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function readAndFreeBuffer(ptr: Deno.PointerValue): Uint8Array {
	if (ptr !== null) {
		const ptrView = new Deno.UnsafePointerView(ptr);
		const len = new DataView(ptrView.getArrayBuffer(4)).getUint32(0);

		const buf = new Uint8Array(len);
		ptrView.copyInto(buf, 4);

		lib.symbols.free_buf(ptr, BigInt(len + 4));

		return buf;
	}

	return new Uint8Array();
}

export async function hash(
	password: string,
	options: Partial<HashOptions> = {},
) {
	if (typeof password !== "string") {
		throw new Argon2Error(
			Argon2ErrorType.InvalidInput,
			"Password argument must be a string.",
		);
	}

	const salt = options.salt ? options.salt : crypto.getRandomValues(
		new Uint8Array(
			Math.max(Math.round(Math.random() * 32), MIN_SALT_SIZE),
		),
	);

	if (salt.length < MIN_SALT_SIZE) {
		throw new Argon2Error(
			Argon2ErrorType.InvalidInput,
			`Input salt is too short: ${salt.length}`,
		);
	}

	const args = encoder.encode(JSON.stringify({
		password,
		options: {
			...options,
			salt: [...salt.values()],
			secret: options.secret ? [...options.secret.values()] : undefined,
			data: options.data
				? [...encoder.encode(JSON.stringify(options.data)).values()]
				: undefined,
		},
	}));

	const result_buf_ptr = await lib.symbols.hash(
		args,
		BigInt(args.byteLength),
	);

	const result = JSON.parse(
		decoder.decode(readAndFreeBuffer(result_buf_ptr)),
	) as {
		result: Array<number>;
		error: string | null;
	};

	if (result.error) {
		throw new Argon2Error(
			Argon2ErrorType.Native,
			"An error occurred executing `hash`",
			result.error,
		);
	}

	return decoder.decode(Uint8Array.from(result.result));
}

export async function verify(
	hash: string,
	password: string,
) {
	const args = encoder.encode(JSON.stringify({
		hash: hash,
		password: password,
	}));

	const result_buf_ptr = await lib.symbols.verify(
		args,
		BigInt(args.byteLength),
	);

	const result = JSON.parse(
		decoder.decode(readAndFreeBuffer(result_buf_ptr)),
	) as {
		result: boolean;
		error: string | null;
	};

	if (result.error) {
		throw new Argon2Error(
			Argon2ErrorType.Native,
			"An error occurred executing `verify`",
			result.error,
		);
	}

	return result.result;
}
