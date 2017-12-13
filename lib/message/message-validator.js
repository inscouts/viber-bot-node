"use strict";

const crypto = require('crypto');

function MessageValidator(logger, authToken) {
	this._logger = logger;
	this._authToken = authToken;
}

MessageValidator.prototype.validateMessage = function(serverSideSignature, message) {
	if (process.env.VIBER_VALIDATION_DISABLE) {
		return true;
	}
	let expected
	if (process.env.VIBER_VALIDATION_STATIC) {
		expected = process.env.VIBER_VALIDATION_STATIC;
		this._logger.debug("Validating static token '%s' == '%s'", serverSideSignature, expected);
	} else {
		expected = this._calculateHmacFromMessage(message);
		this._logger.debug("Validating signature '%s' == '%s'", serverSideSignature, expected);
	}
	return serverSideSignature == expected;
};

MessageValidator.prototype._calculateHmacFromMessage = function(message) {
	return crypto.createHmac("sha256", this._authToken).update(message).digest("hex");
};

module.exports = MessageValidator;