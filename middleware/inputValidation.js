const { body } = require("express-validator");

// Set up input validation rules
exports.registrationValidationRules = [
	body("username").isEmail().withMessage("Please enter a valid email address."),
	body("password")
		.isLength({ min: 8 })
		.withMessage("Password must be at least 8 characters."),
];

exports.loginValidationRules = [
	body("username").isEmail().withMessage("Please enter a valid email address."),
	body("password").notEmpty().withMessage("Password cannot be empty."),
];
