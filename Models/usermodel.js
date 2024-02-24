const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    trim: true,
    required: [true, "A user must have a name:"],
  },
  email: {
    type: String,
    trim: true,
    required: [true, "Please enter your Email Id:"],
    unique: [true, "There is already a account with this email Id:"],
    lowercase: true,
    //validate: [validator.isEmail, "Please provide a valid email id:"],
  },
  role: {
    type: String,
    enum: ["user", "admin"],
    default: "user",
  },
  password: {
    type: String,
    trim: true,
    required: [true, "A user must have a password:"],
    minlength: [6, "Password length must be between 6 and 20:"],
    maxlength: [15, "password length must be between 6 and 20:"],
    select: false,
  },
  confirmPassword: {
    type: String,
    trim: true,
    required: [true, "please confirm the password:"],
    minlength: [6, "Password length must be between 6 and 15:"],
    maxlength: [15, "Password length must be between 6 and 15:"],
    validate: {
      //this only work with create and SAVE !!!
      validator: function (val) {
        return val === this.password;
      },
      message: "Confirm Password did not match:",
    },
  },
  passwordChangedAt: {
    type: Date,
  },
  passwordResetToken: String,
  passwordResetExpires: Date,
  active: {
    type: Boolean,
    default: true,
    select: false,
  },
 
});

//all these middlewares works only with SAVE and CREATE

//to show only active users
userSchema.pre(/^find/, function (next) {
  this.find({ active: { $ne: false } });
  next();
});
//to set change time whenever password changes
userSchema.pre("save", function (next) {
  if (!this.isModified("password") || this.isNew) return next();
  this.passwordChangedAt = Date.now() - 1000; //because sometimes token get send before actually saving, so while asking for data token is found expired.
  next();
});
//
userSchema.pre("save", async function (next) {
  //only run this function if password is midified
  if (!this.isModified("password")) return next();
  //hash the password with cost of 12
  this.password = await bcrypt.hash(this.password, 12);
  //delete passwordconfirm field
  this.confirmPassword = undefined;
  next();
});
//

//to check if password is correct while loging in
userSchema.methods.correctPassword = async function (
  candidatePasssword,
  userPassword
) {
  //userpassword is required as this.password do not work because of select to false
  return await bcrypt.compare(candidatePasssword, userPassword);
};
//to create a password reset token
userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex"); //create token in hexadecimal string form
  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex"); //encrypte and add to schema
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;
  return resetToken; //we send uncrypted token and then save it as encrypted
};
//to check if password is changed earlier
userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

const User = mongoose.model("User", userSchema);
module.exports = User;
