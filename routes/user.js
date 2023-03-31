const express = require("express");
const { checkAuthenticated } = require("../middleware/auth");
const User = require("../models/User");

const router = express.Router();

// Home GET route renders home page
router.get("/", (req, res) => {
	res.render("home");
});

router.get("/submit", checkAuthenticated, (req, res) => {
	res.render("submit");
});

router.post("/submit", checkAuthenticated, async (req, res) => {
	const submittedSecret = req.body.secret;
	try {
		user = await User.findById(req.user.id);
		if (user) {
			user.secret = submittedSecret;
			await user.save();
			res.redirect("/secrets");
		}
	} catch {
		console.log(err);
		res.redirect("/submit");
	}
});

// Secrets route renders secrets page
router.get("/secrets", checkAuthenticated, async (req, res) => {
	try {
		foundUsers = await User.find();
		if (foundUsers) {
			res.render("secrets", { usersWithSecrets: foundUsers });
		}
	} catch (err) {
		console.log(err);
	}
});

module.exports = router;
