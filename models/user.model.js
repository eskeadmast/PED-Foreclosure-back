const crypto = require("crypto");
const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcryptjs");

const userSchema = mongoose.Schema({
  name: {
    type: String,
    required: [true, "Please enter your fullvname"],
    trim: true,
  },
  role: {
    type: String,
    enum: ["user", "admin", "senior"],
    default: "user",
  },
  password: {
    type: String,
    required: [true, "Please provide a password"],
    minlength: 8,
    select: false,
  },
  confirmPassword: {
    type: String,
    required: [true, "Please confirm the password"],
    validate: {
      // This works only on CREATE & SAVE
      validator: function (el) {
        return el === this.password;
      },
      message: "Passwords are not the same!",
    },
  },
  username: {
    type: String,
    unique: true,
    lowercase: true,
  },
  // foreclosures: [
  //   {
  //     type: mongoose.Schema.Types.ObjectId,
  //     ref: 'ForeclosureData', // references User collection
  //   },
  // ],
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  active: { type: Boolean, default: true, select: false },
});

function randomFourDigits() {
  return Math.floor(1000 + Math.random() * 9000);
}

// userSchema.pre('save', function () {
//   if (this.name && !this.username) {
//     const parts = this.name.trim().split(' ');
//     const firstName = parts[0]; // only use first word
//     this.username = `${firstName.toLowerCase()}${randomFourDigits()}`;
//   }
// });

userSchema.pre("save", async function () {
  // Create User Name
  if (this.name && !this.username) {
    const parts = this.name.trim().split(" ");
    const firstName = parts[0]; // only use first word
    this.username = `${firstName.toLowerCase()}${randomFourDigits()}`;
  }
  // Only run this function if password is actually modified
  if (!this.isModified("password")) return;

  // Hassh password with cost of 12
  this.password = await bcrypt.hash(this.password, 12);

  // Delete password confirm field
  this.confirmPassword = undefined;
});
userSchema.pre("save", function () {
  if (!this.isModified("password") || this.isNew) return;
  this.passwordChangedAt = Date.now() - 1000;
});
// comparig passwords
userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword,
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};
userSchema.pre(/^find/, function () {
  // this points to current query
  this.find({ active: { $ne: false } });
});
// check if user changed password after
userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10,
    );
    // console.log(changedTimestamp, JWTTimestamp);
    return JWTTimestamp < changedTimestamp;
  }
  //  false means not changed
  return false;
};

// Password reset token
userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex");

  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");
  // console.log({ resetToken }, this.passwordResetToken);
  this.passwordResetExpires = Date.now() + 10 * 10 * 60 * 1000;

  return resetToken;
};
const User = mongoose.model("User", userSchema);

module.exports = User;
