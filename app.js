require("dotenv").config();
const express = require("express");
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const MongoStore = require("connect-mongo");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();
const port = parseInt(process.env.PORT) || 3000;
const db_url = process.env.DB_STRING;

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));

// set up session before passport
app.use(
	session({
		secret: process.env.SECRET,
		resave: false,
		saveUninitialized: false,
		store: MongoStore.create({
			mongoUrl: db_url,
			autoReconnect: true,
		}),
	})
);

// set up passport
app.use(passport.initialize());
app.use(passport.session());

// Set up rate limiting
const registerLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 100, // Limit each IP to 100 requests per windowMs
	message: "Too many registration attempts, please try again later.",
});

const loginLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 100, // Limit each IP to 100 requests per windowMs
	message: "Too many login attempts, please try again later.",
});

// Set up input validation rules
const registrationValidationRules = [
	body("username").isEmail().withMessage("Please enter a valid email address."),
	body("password")
		.isLength({ min: 8 })
		.withMessage("Password must be at least 8 characters."),
];

const loginValidationRules = [
	body("username").isEmail().withMessage("Please enter a valid email address."),
	body("password").notEmpty().withMessage("Password cannot be empty."),
];

// Middleware to check if the user can bypass login page
function checkAlreadyAuthenticated(req, res, next) {
	if (req.isAuthenticated()) {
		console.log("User is already authenticated, redirecting to secrets page");
		res.redirect("/secrets");
	} else {
		console.log("User is not authenticated, allowing access to login page");
		next();
	}
}

// Middleware to check if the user is authenticated
function checkAuthenticated(req, res, next) {
	if (req.isAuthenticated()) {
		console.log("User is allowed to view this page");
		next();
	} else {
		console.log(
			"User is not allowed to view this page, redirecting to login page"
		);
		res.redirect("/login");
	}
}

// Middleware to log out user
function customLogout(req, res, next) {
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
}

// connect to mongo database and define user schema
mongoose
	.connect(db_url, { useNewUrlParser: true, useUnifiedTopology: true })
	.then(() => {
		console.log("DB connected");
		// Start server
		app.listen(port, () => {
			console.log("Server started on port " + port);
		});
	})
	.catch((err) => {
		console.log(err);
	});

const userSchema = mongoose.Schema({
	email: String,
	password: String,
});

// use passport-local-mongoose to add methods to user schema
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// create model
const User = new mongoose.model("User", userSchema);

// create local strategy for passport
passport.use(User.createStrategy());

// serialize and deserialize user
passport.serializeUser((user, done) => {
	done(null, { _id: user._id, googleId: user.googleId });
});

passport.deserializeUser(async (serializedUser, done) => {
	try {
		if (serializedUser.googleId) {
			const user = await User.findOne({ googleId: serializedUser.googleId });
			done(null, user);
		} else {
			const user = await User.findById(serializedUser._id);
			done(null, user);
		}
	} catch (err) {
		done(err, null);
	}
});

// Set up Google OAuth2 strategy with Passport.js
passport.use(
	new GoogleStrategy(
		{
			clientID: process.env.GOOGLE_CLIENT_ID,
			clientSecret: process.env.GOOGLE_CLIENT_SECRET,
			callbackURL: "/auth/google/callback",
		},
		async (accessToken, refreshToken, profile, done) => {
			try {
				const existingUser = await User.findOne({
					username: "google-" + profile.id,
				});

				if (existingUser) {
					// If the user already exists, pass the existing user to the done() function
					done(null, existingUser);
				} else {
					// If the user doesn't exist, create a new user and pass it to the done() function
					const newUser = await new User({
						username: "google-" + profile.id,
						googleId: profile.id,
					}).save();
					done(null, newUser);
				}
			} catch (err) {
				done(err, null);
			}
		}
	)
);

// Google authentication routes
app.get(
	"/auth/google",
	checkAlreadyAuthenticated,
	passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
	"/auth/google/callback",
	passport.authenticate("google", { failureRedirect: "/login" }),
	(req, res) => {
		res.redirect("/secrets");
	}
);

// Home GET route renders home page
app.get("/", (req, res) => {
	res.render("home");
});

// Login GET route renders login page
app.get("/login", checkAlreadyAuthenticated, (req, res) => {
	res.render("login");
});

// Register GET route renders register page
app.get("/register", (_req, res) => {
	res.render("register");
});

// Register POST route connects to database to check if user exists and if password is correct
app.post(
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
app.post(
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

// Secrets route renders secrets page
app.get("/secrets", checkAuthenticated, (req, res) => {
	res.render("secrets");
});

// Logout route redirects to home page
app.get("/logout", customLogout);
