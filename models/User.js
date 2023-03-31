const mongoose = require("mongoose");
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");

const userSchema = mongoose.Schema({
  email: String,
  password: String,
  secret: String,
});

// use passport-local-mongoose to add methods to user schema
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// create model
const User = new mongoose.model("User", userSchema);

module.exports = User;
