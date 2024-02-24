const User = require("./../Models/usermodel");
const jwt = require("jsonwebtoken");
const { promisify } = require("util");
const sendEmail = require("./../utils/email");
const crypto = require("crypto");

const createSendToken = (user, statusCode, res) => {
 // console.log("in createSendToken");
  const token = signToken(user._id);
 
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
  };
  //will only allow this to send cookie if it is https
  if (process.env.NODE_ENV === "production") cookieOptions.secure = true;

  //browser can not access and change this cookie. only recieve and send
  res.cookie("jwt", token, cookieOptions);
  //hide password even when creating new user though cookie is not saved
  user.password = undefined;
  //console.log(res.headers);
  res.status(statusCode).json({
    status: "success",
    token, 
    data: { user: user },
  });
};

const signToken = id => {
 
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};
exports.signup = async (req, res) => {
  try {
    // console.log("in try");
    const newUser = await User.create({
     name: req.body.name,
      email: req.body.email,
      password: req.body.password,
      confirmPassword: req.body.confirmPassword,
    });
    // console.log("newUser",newUser);
   //  console.log("in signup");
    createSendToken(newUser, 201, res);
  } catch (err) {
     //console.log("in err");
    res.status(200).json({
      status: "failed",
      message: err + "",
    });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(200).json({
      status: "failed",
      message: "Please fill the complete form",
    });
    return;
  }
  //check if user exists & password is correct
  const user = await User.findOne({ email }).select("+password");

  if (!user || !(await user.correctPassword(password, user.password))) {
    res.status(200).json({
      status: "failed",
      message: "Incorrect email or password",
    });
    return;
  }
  //if everything is ok send token to client
  createSendToken(user, 200, res);
};
exports.logout = (req, res) => {
  //just send a corrupted cookie

  const cookieOptions = {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  };
  if (process.env.NODE_ENV === "production") cookieOptions.secure = true;
  //no need to send cookie via https as it is already corrupted
  res.cookie("jwt", "logout", cookieOptions);

  res.status(200).json({
    status: "success",
  });
};

exports.forgotPassword = async (req, res) => {
  //1. find user with that email
  if (!req.body.email) {
    res.status(200).json({
      status: "failed",
      message: "Please fill the complete form",
    });
    return;
  }
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    res.status(200).json({
      status: "failed",
      message: "There is no user registered with this email",
    });
    return;
  }
  //2. get a reset token and save it
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false }); //deactivate all validators in schema as email should be unique
  //3.sending token to user's email
  // const resetURL = `${req.protocol}://${req.get(
  //   "host"
  // )}/resetPassword/${resetToken}`;
  const resetURL=`https://webmaker-9smd.onrender.com/resetPassword/${resetToken}`
  const message = `Forgot your password? Submit a patch request with your new password with confirmPassword to: 
    ${resetURL}\n If you did't forgot your password, please ignore this email`;
    // console.log("resetURL", resetURL)
    // console.log("message",message)
      
  try {
   
    await sendEmail({
      email: user.email,
      subject: "Your password reset token (valid for 10 minutes)",
      message,
    });
    res.status(200).json({
      status: "success",
      message: "Token send to email",
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });
    res.status(200).json({
      status: "failed",
      message: "Email could not be send"+err,
    });
  }
};

exports.resetPassword = async (req, res) => {
  if (!req.body.password || !req.body.confirmPassword) {
    res.status(200).json({
      status: "failed",
      message: "Please fill the complete form",
    });
    return;
  }
  const hasedToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");

  //2. check if token is expired and user still exists and then change the password
  const user = await User.findOne({
    passwordResetToken: hasedToken,
    passwordResetExpires: { $gt: Date.now() },
  });
  if (!user) {
    res.status(200).json({
      status: "failed",
      message: "Token is invalid or expired",
    });
    return;
  }
  try {
    user.password = req.body.password;
    user.confirmPassword = req.body.confirmPassword;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();
  } catch (err) {
    res.status(200).json({
      status: "failed",
      message: "Confirm Password did not match",
    });
    return;
  }

  //3. update changePassword property for the user through userschema.pre(save)

  //4. Log the user in and send jwt
  createSendToken(user, 200, res);
};

exports.updatePassword = async (req, res) => {
  //1. get user
  if (
    !req.body.password ||
    !req.body.newPassword ||
    !req.body.confirmNewPassword
  ) {
    res.status(200).json({
      status: "failed",
      message: "Please fill the complete form",
    });
    return;
  }
  const user = await User.findById(req.user.id).select("+password");

  //2. check if password is correct
  if (!(await user.correctPassword(req.body.password, user.password))) {
    res.status(200).json({
      status: "failed",
      message: "Incorrect password",
    });
    return;
  }

  //3. update the password
  try {
    user.password = req.body.newPassword;
    user.confirmPassword = req.body.confirmNewPassword;
    await user.save();
  } catch (err) {
    res.status(200).json({
      status: "failed",
      message: "Confirm Password did not match",
    });
    return;
  }

  //4. login the user
  createSendToken(user, 200, res);
};

const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach((el) => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};
exports.updateData = async (req, res) => {
  //1. create error if user send password data
  if (req.body.password || req.body.confirmPassword) {
    res.status(200).json({
      status: "failed",
      message:
        "You can not update password through this route.Please use /updatePassword ",
    });
  }

  //2.filter out fields that are not allowed to update
  const filteredBody = filterObj(req.body, "name");

  //3. update the data
  //we can't just save updates because we need only some validations
  const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
    new: true,
    runValidators: true,
  });

  res.status(200).json({
    status: "success",
    data: {
      user: updatedUser,
    },
  });
};

exports.addHistory = async (req, res) => {
  //we can't just save updates because we need only some validations
  try {
    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      {
        $push: {
          history: req.body.history,
        },
      },
      {
        new: true,
        runValidators: true,
      }
    );

    res.status(200).json({
      status: "success",
      data: {
        user: updatedUser,
      },
    });
  } catch (err) {
    res.status(400).json({
      status: "failed",
      message: err + "",
    });
  }
};

exports.deleteHistory = async (req, res) => {
  try {
    //we can't just save updates because we need only some validations
    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      {
        $pull: {
          history: { _id: req.body.history._id },
        },
      },
      {
        new: true,
        runValidators: true,
      }
    );

    res.status(200).json({
      status: "success",
      data: {
        user: updatedUser,
      },
    });
  } catch (err) {
    res.status(400).json({
      status: "failed",
      message: err + "",
    });
  }
};

exports.deleteMe = async (req, res) => {
  await User.findByIdAndUpdate(req.user.id, { active: false });

  res.status(204).json({
    status: "success",
    data: null,
  });
};
exports.protect = async (req, res, next) => {
  //1.Getting token and check if it's there
  let token;
//   let freshUser;
  //  let decodedToken;
  res.cookie("myCookie", "cookieValue", {
    secure: true, 
    httpOnly: true,
  
  });

  if (req.cookies&&req.cookies.jwt) {
    token = req.cookies.jwt;
  }

//   if (!token) {
//     res.status(400).json({
//       status: "falied",
//       message: "Login to get access",
//     });
//     return;
//   }

  // let token;
  // if (
  //   req.headers.authorization &&
  //   req.headers.authorization.startsWith('Bearer')
  // ) {
  //   token = req.headers.authorization.split(' ')[1];
  // }

   if (!token) {
    res.status(500).json({
      status: "falied",
      message: "Login to get access",
    });
    return;
  }

  //2.Verification of token
  let decodedToken = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  //actually jwt.verify is already a asycn , so to continue as same we promisify otherwise provide callback

  if (!decodedToken) {
    res.status(400).json({
      status: "falied",
      message: "Please login again!",
    });
    return;
  }

  //3.Check if user still exixts
  let freshUser = await User.findById(decodedToken.id);
  if (!freshUser) {
    res.status(400).json({
      status: "falied",
      message: "User with this id no longer exists",
    });
    return;
  }

  //4. check if password was changed after creation of token
  if (freshUser.changedPasswordAfter(decodedToken.iat)) {
    res.status(400).json({
      status: "failed",
      message: "User changed password recently.Please login again!",
    });
    return;
  }
  //5. grant permission to access
  req.user = freshUser;
 
  next();
};
exports.sendEmail = async (req, res) => {
  try {
    
    await sendEmail({
      email: process.env.EMAIL_RECEIVER,
      subject: `WebMaker from ${req.body.email} by ${req.body.name}`,
      message: req.body.message,
    });
    res.status(200).json({
      status: "success",
      message: "Message send",
    });
  } catch (err) {
    res.status(200).json({
      status: "failed",
      message: "Email could not be send",
    });
  }
};
exports.restrictTo = (...roles) => {
  //because arguments can not be passed to meddleware
  //so return a wrapper which is actual fucntion we want to create
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      res.status(403).json({
        status: "failed",
        message: "You do not have the permission to perform this action",
      });
      return;
    }
    next();
  };
};