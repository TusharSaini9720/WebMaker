const express = require("express");
const userController = require("./../Controller/usercontroller");
const authController = require("./../Controller/Authcontroller");
const userRoutes = express.Router();

//for users
userRoutes.post("/signup", authController.signup,authController.signupEmail);
userRoutes.post("/login", authController.login);
userRoutes.get("/logout", authController.logout);
userRoutes.post("/forgotPassword",authController.forgotPassword);
userRoutes.patch("/resetPassword/:token", authController.resetPassword);
userRoutes.patch(
  "/updatePassword",
  authController.protect,
  authController.updatePassword
);
userRoutes.patch('/updateMe', authController.protect, userController.updateMe);
userRoutes.delete('/deleteMe', authController.protect, userController.deleteMe);

userRoutes
  .get('/',
    authController.protect,
    authController.restrictTo("admin"),
    userController.getAllUsers
  )

  userRoutes.post("/sendEmail", authController.sendEmail);
module.exports=userRoutes;