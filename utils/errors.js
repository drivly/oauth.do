export class UnknownError extends Error {
	constructor({ name = 'UnknownError', message }) {
		super(message);
		this.name = name;
	}
}

export class ConfigError extends UnknownError {
	constructor({ message }) {
		super({ name: 'ConfigError', message });
	}
}

export class TokenError extends UnknownError {
	constructor({ message }) {
		super({ name: 'TokenError', message });
	}
}

export class ProviderGetUserError extends UnknownError {
	constructor({ message }) {
		super({ name: 'ProviderGetUserError', message });
	}
}

export class ProviderSendOtpError extends UnknownError {
	constructor({ message }) {
		super({ name: 'ProviderSendOtpError', message });
	}
}

export class ProviderVerifyOtpError extends UnknownError {
	constructor({ message }) {
		super({ name: 'ProviderVerifyOtpError', message });
	}
}
