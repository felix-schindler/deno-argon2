import { type HashOptions, MIN_SALT_SIZE, version } from "./common.ts";
import { Argon2Error, Argon2ErrorType } from "./error.ts";
import { dlopen, type FetchOptions } from "./deps.ts";

const LOCAL = Deno.env.get("LOCAL");

/**
 * Gets the Rust target triple for the current OS and architecture.
 * @returns The target triple string
 */
function getTarget(): string {
	const arch = Deno.build.arch;
	const os = Deno.build.os;

	if (os === "windows") {
		return `${arch}-pc-windows-msvc`;
	} else if (os === "darwin") {
		return `${arch}-apple-darwin`;
	} else if (os === "linux") {
		return `${arch}-unknown-linux-gnu`;
	} else {
		throw new Error(`Unsupported OS: ${os}`);
	}
}

/**
 * Generates a local file URL for the target release directory based on the current module's location.
 * @returns The local file path as a string, adjusted for the operating system. On Windows, the path is converted to use backslashes, and any leading slash is removed.
 */
function getLocalUrl(): string {
	const url = new URL(`../target/${getTarget()}/release`, import.meta.url);

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

/**
 * Configuration options for fetching the Argon2 module, determining whether to fetch from a local source or a remote URL.
 */
const FETCH_OPTIONS: FetchOptions = {
	name: LOCAL ? "deno_argon2" : "deno_argon2-" + Deno.build.arch,
	url: LOCAL
		? getLocalUrl()
		: `https://github.com/felix-schindler/deno-argon2/releases/download/v${version()}/`,
	cache: LOCAL ? "reloadAll" : "use",
};

/**
 * An object that defines the symbols for interacting with native functions related to Argon2 operations.
 * This object is used to map the function signatures of the native methods, specifying their parameters, return types, and other properties.
 */
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

/**
 * Reads data from a native buffer pointed to by a given pointer and then frees the buffer to avoid memory leaks.
 * @param ptr - A pointer to the native buffer that contains the data to be read. If the pointer is `null`, an empty `Uint8Array` is returned.
 * @returns A `Uint8Array` containing the data read from the buffer. If the pointer is `null`, an empty `Uint8Array` is returned.
 */
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

/**
 * Hashes a password using the Argon2 algorithm with the specified options. This function also handles errors related to input validation and native execution.
 * @param password The password to be hashed. This must be a string; otherwise, an `Argon2Error` is thrown.
 * @param [options={}] Optional configuration for the hashing operation. This may include settings like salt, secret, memory cost, time cost, and more. If not provided, default options are used.
 * @returns A promise that resolves to the resulting hash encoded as a string.
 * @throws {Argon2Error} - Throws an `Argon2Error` if the input password is not a string, the salt is too short, or if a native error occurs during hashing.
 */
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

/**
 * Verifies if a given password matches the provided Argon2 hash. This function performs the verification by calling a native function and handles any errors that occur during the process.
 * @param hash - The Argon2 hash that the password is being compared against. This must be a valid hash string.
 * @param password - The password to be verified against the hash. This must be a string.
 * @param secret - An optional secret string that was used during hashing. If provided, the secret must match the one used during hashing; otherwise, the verification fails.
 * @param additionalData - An optional Uint8Array of additional data that was used during hashing. If provided, the additional data must match the one used during hashing; otherwise, the verification fails.
 * @returns A promise that resolves to `true` if the password matches the hash, or `false` otherwise.
 * @throws {Argon2Error} Throws an `Argon2Error` if a native error occurs during the verification process.
 */
export async function verify(
	hash: string,
	password: string,
	secret?: Uint8Array,
	additionalData?: unknown,
) {
	const args = encoder.encode(JSON.stringify({
		hash: hash,
		password: password,
		secret: secret ? [...secret.values()] : undefined,
		data: additionalData
			? [...encoder.encode(JSON.stringify(additionalData)).values()]
			: undefined,
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
