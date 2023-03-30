exports.checkAlreadyAuthenticated = (req, res, next) => {
	if (req.isAuthenticated()) {
		console.log("User is already authenticated, redirecting to secrets page");
		res.redirect("/secrets");
	} else {
		console.log("User is not authenticated, allowing access to login page");
		next();
	}
};

exports.checkAuthenticated = (req, res, next) => {
	if (req.isAuthenticated()) {
		console.log("User is allowed to view this page");
		next();
	} else {
		console.log(
			"User is not allowed to view this page, redirecting to login page"
		);
		res.redirect("/login");
	}
};

exports.customLogout = (req, res, next) => {
	if (req.session) {
		req.session.destroy((err) => {
			if (err) {
				return next(err);
			} else {
				return res.redirect("/");
			}
		});
	} else {
		return res.redirect("/");
	}
};
