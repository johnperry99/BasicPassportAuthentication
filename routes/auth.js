const express = require("express");
const passport = require("passport");
const {
	checkAlreadyAuthenticated,
	customLogout,
} = require("../middleware/auth");
const { registerLimiter, loginLimiter } = require("../middleware/rateLimit");

const {
	registrationValidationRules,
	loginValidationRules,
} = require("../middleware/inputValidation");

const router = express.Router();
// Google authentication routes
router.get(
	"/auth/google",
	checkAlreadyAuthenticated,
	passport.authenticate("google", { scope: ["profile", "email"] })
);

router.get(
	"/auth/google/callback",
	passport.authenticate("google", { failureRedirect: "/" }),
	(req, res) => {
		res.redirect("/secrets");
	}
);

// Register POST route connects to database to check if user exists and if password is correct
router.post(
	"/register",
	registerLimiter,
	registrationValidationRules,
	async (req, res) => {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				return res.status(400).json({ errors: errors.array() });
			}
			await User.register({ username: req.body.username }, req.body.password);
			passport.authenticate("local")(req, res, () => {
				res.redirect("/secrets");
			});
		} catch (err) {
			console.log(err);
			res.redirect("/register");
		}
	}
);

// Login route connects to database to check if user exists and if password is correct
router.post(
	"/login",
	loginLimiter,
	loginValidationRules,
	(req, res, next) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({ errors: errors.array() });
		}
		next();
	},
	passport.authenticate("local", {
		successRedirect: "/secrets",
		failureRedirect: "/login",
		session: true,
	})
);

// Logout route redirects to home page
router.get("/logout", customLogout);

module.exports = router;
