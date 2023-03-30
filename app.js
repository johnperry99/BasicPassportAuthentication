require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const MongoStore = require("connect-mongo");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const User = require(__dirname + "/models/User");
const { registerLimiter, loginLimiter } = require(__dirname + "/middleware/rateLimit");
const {
	registrationValidationRules,
	loginValidationRules,
} = require(__dirname + "/middleware/inputValidation");
const {checkAlreadyAuthenticated, checkAuthenticated, customLogout} = require(__dirname + "/middleware/auth");
const authRoutes = require(__dirname + "/routes/auth");

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

app.use(authRoutes);

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

app.get("/submit", checkAuthenticated, (req, res) => {
	res.render("submit");
});

app.post("/submit", checkAuthenticated, async (req, res) => {
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
app.get("/secrets", checkAuthenticated, async (req, res) => {
	try {
		foundUsers = await User.find();
		if (foundUsers) {
			res.render("secrets", { usersWithSecrets: foundUsers });
		}
	} catch (err) {
		console.log(err);
	}
});
