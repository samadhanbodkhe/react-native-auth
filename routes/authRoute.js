const authController = require("../controller/authController")
const router = require("express").Router()

router
    .post("/login", authController.loginUser)
    .post("/register", authController.registerUser)
    .post("/logout", authController.logoutUser)
    .post("/verify-otp", authController.verifyOpt)
    .post("/verify-otp", authController.verifyOpt)
    .post("/verifyOtpForReset", authController.verifyOtpForReset)
    .post("/resetPassword", authController.resetPassword)

module.exports = router