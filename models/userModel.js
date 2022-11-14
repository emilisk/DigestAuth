//import mongoose
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const mongooseFieldEncryption =
  require("mongoose-field-encryption").fieldEncryption;
//import crypto
const crypto = require("crypto");

//create schema
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});

userSchema.plugin(mongooseFieldEncryption, {
  fields: ["password"],
  secret: process.env.SECRET,
  saltGenerator: function (secret) {
    return "1234567890123456";
    // should ideally use the secret to return a string of length 16,
    // default = `const defaultSaltGenerator = secret => crypto.randomBytes(16);`,
    // see options for more details
  },
});

// userSchema.plugin(encrypt, {
//   secret: process.env.SECRET,
//   encryptedFields: ["password"],
// });

//generate password reset hash
userSchema.methods.passwordResetHash = function () {
  //create hash object, then create a sha512 hash of the user's current password
  //and return hash
  const resetHash = crypto
    .createHash("sha512")
    .update(this.password)
    .digest("hex");
  return resetHash;
};

//verify password reset hash
userSchema.methods.verifyPasswordResetHash = function (resetHash = undefined) {
  //regenerate hash and check if they are equal
  return this.passwordResetHash() === resetHash;
};

//our model
const User = mongoose.model("User", userSchema);
module.exports = User;
