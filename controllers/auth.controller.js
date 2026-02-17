const crypto = require('crypto');
const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/user.model');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');

const signToken = id => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const days = Number(process.env.JWT_COOKIE_EXPIRES_IN) || 90;
if (isNaN(days)) throw new Error('JWT_COOKIE_EXPIRES_IN must be a number');

const cookieOptions = {
  maxAge: days * 24 * 60 * 60 * 1000,
  httpOnly: true,
  secure: false, // true if using HTTPS
  sameSite: 'lax',
};
const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);

  // create and send cookies
  if (process.env.NODE_ENV === 'production') {
    cookieOptions.secure = true;
    cookieOptions.sameSite = 'none';
  }
  res.cookie('jwt', token, cookieOptions);

  const safeUser = user.toObject();
  delete safeUser.password;
  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user: safeUser,
    },
  });
};
exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    password: req.body.password,
    confirmPassword: req.body.confirmPassword,
  });
  const safeUser = newUser.toObject();
  delete safeUser.password;
  // const token = signToken(newUser._id);

  res.status(201).json({
    status: 'success',
    // token,
    data: {
      user: safeUser,
    },
  });
});

exports.login = catchAsync(async (req, res, next) => {
  const { username, password } = req.body;

  //   1) check if username & password exists
  if (!username || !password) {
    return next(new AppError('Please provide username and password', 400));
  }
  //    2)check if the user exists && Password is correct
  const user = await User.findOne({ username }).select('+password');
  console.log(user);

  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect email or password', 401));
  }
  //   3) If everything is ok sign in
  createSendToken(user, 200, res);
});

// Authentication
exports.protect = catchAsync(async (req, res, next) => {
  let token;

  // 1) Get token
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies && req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  if (!token) {
    return next(
      new AppError('You are not logged in. Please login again.', 401),
    );
  }

  let decoded;

  // 2) Verify token SAFELY
  try {
    decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
  } catch (err) {
    // 🔥 THIS IS THE FIX
    if (err.name === 'TokenExpiredError') {
      return next(
        new AppError('Your session has expired. Please login again.', 401),
      );
    }

    return next(new AppError('Invalid token. Please login again.', 401));
  }

  // 3) Check user still exists
  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    return next(
      new AppError('User belonging to this token no longer exists.', 401),
    );
  }

  // 4) Password changed?
  if (currentUser.changedPasswordAfter(decoded.iat)) {
    return next(
      new AppError('Password recently changed. Please login again.', 401),
    );
  }

  req.user = currentUser;
  next();
});

// Authorization
// since we can not pass arguments to middleware we wrap it with another function
exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    // roles is an array
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError(
          'You do not have a permission to perform this action',
          403,
        ),
      );
    }
    next();
  };
};

exports.forgotPassword = catchAsync(async (req, res, next) => {
  // 1) get user based on POSTed username
  const user = await User.findOne({ username: req.body.username });
  if (!user) {
    return next(new AppError('There is no user with this username', 404));
  }
  // 2) Generate the random reset token
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });
  // 3)Send it to the user's email
  // const resetURL = `${req.protocol}://${req.get('host')}/api/v1/users/resetPassword/${resetToken}`;
  res.status(200).json({
    status: 'success',
    resetToken,
  });
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  // 1) Get user based on the token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });
  // 2) if token has not expired and there is user, set new password
  if (!user) {
    return next(new AppError('Token is invalid or has expired', 400));
  }
  user.password = req.body.password;
  user.confirmPassword = req.body.confirmPassword;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;

  await user.save();
  // 3) Update changedpasswordat property for the user
  // 4) log the user in, send Jwt
  createSendToken(user, 200, res);
});
exports.updatePassword = catchAsync(async (req, res, next) => {
  // 1) Get the user from the collection
  const user = await User.findById(req.user.id).select('+password');
  // 2) Check if POSTed password is correct
  if (!user.correctPassword(req.body.currentPassword, user.password)) {
    return next(new AppError('Your current password is wrong.', 401));
  }
  // 3) If so, update Password
  user.password = req.body.password;
  user.confirmPassword = req.body.confirmPassword;
  await user.save();

  // 4) Log user, send jwt
  createSendToken(user, 200, res);
});
