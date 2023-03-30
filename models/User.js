const mongoose = require("mongoose");
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");
const mongooseEncryption = require("mongoose-encryption");

const userSchema = mongoose.Schema({
  email: String,
  password: String,
  secret: String,
});

// use passport-local-mongoose to add methods to user schema
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
userSchema.plugin(mongooseEncryption, {
  secret: process.env.SECRET,
  encryptedFields: ["secret"],
});

// create model
const User = new mongoose.model("User", userSchema);

module.exports = User;
