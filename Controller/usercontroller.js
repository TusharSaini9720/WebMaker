
const User = require('./../Models/usermodel');

exports.getAllUsers = async (req, res, next) => {
  try{const users = await User.find();
  // SEND RESPONSE
  res.status(200).json({
    status: 'success',
    results: users.length,
    data: {
      users
    }
  });}
  catch(err){
    res.status(400).json({
    status:"fail",
    message: err+" "
})}
};

exports.updateMe = async (req, res, next) => {
    // 1) Create error if user POSTs password data
  try { if (req.body.password || req.body.passwordConfirm) {
      return next(
        new AppError(
          'This route is not for password updates. Please use /updateMyPassword.',
          400
        )
      );
    }
  
    // 2) Filtered out unwanted fields names that are not allowed to be updated
    const filteredBody = filterObj(req.body, 'name', 'email');
  
    // 3) Update user document
    const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
      new: true,
      runValidators: true
    });
  
    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });}
    catch(err){
        res.status(400).json({
        status:"fail",
        message: err+" "
    })}
  };
  
  exports.deleteMe = async (req, res, next) => {
    try{await User.findByIdAndUpdate(req.user.id, { active: false });
  
    res.status(204).json({
      status: 'success',
      data: null
    });}
    catch(err){
        res.status(400).json({
            status:"fail",
            message: err+" "
        })
    }
  };