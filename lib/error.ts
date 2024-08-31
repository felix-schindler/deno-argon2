/**
 * This module contains custom errors for Argon2 operations.
 * @module
 */

/**
 * Argon2ErrorType defines the possible types of errors that can occur when using the Argon2 hashing algorithm.
 */
export enum Argon2ErrorType {
	/** Indicates that the operation failed due to insufficient permissions. */
	UnmeetPermission = "UnmeetPermission",
	/** Indicates that the input provided to the function was invalid or malformed. */
	InvalidInput = "InvalidInput",
	/** Represents errors that originate from the underlying native library used for Argon2 operations. */
	Native = "Native",
}

/**
 * Argon2Error is a custom error class that encapsulates errors related to Argon2 operations.
 * It includes additional information about the type of error and an optional original error.
 */
export class Argon2Error extends Error {
	/**
	 * @param type - The type of the Argon2 error, as defined in the Argon2ErrorType enum.
	 * @param message - A descriptive message providing details about the error.
	 * @param [originalError] - An optional parameter that captures the original error object, if any.
	 */
	constructor(
		public readonly type: Argon2ErrorType,
		message: string,
		public readonly originalError?: unknown,
	) {
		super(message);
	}

	/**
	 * @description Overrides the default `name` property to include the Argon2 error type.
	 * @returns Returns the name of the error, which includes the error type.
	 */

	get name(): string {
		return `Argon2Error(${this.type})`;
	}
}
