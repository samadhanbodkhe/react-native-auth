const asyncHandler = require("express-async-handler")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const validator = require("validator")
const sendEmail = require("../utils/email")
const AuthModal = require("../modal/AuthModal")

exports.registerUser = asyncHandler(async (req, res) => {
    const { name, email, password, phone } = req.body


    //validation

    if (!name || !email || !password || !phone) {
        return res.status(400).json({ message: "All field are required" })
    }

    if (!validator.isEmail(email)) {
        return res.status(400).json({ message: "Please provide is valid email" })
    }

    if (!validator.isStrongPassword(password)) {
        return res.status(400).json({ message: "Please provide is strong password" })
    }

    //validation

    const result = await AuthModal.findOne({ email })

    if (result) {
        return res.status(400).json({ message: "Email already register with us" })
    }

    const phoneExist = AuthModal.findOne({ phone })

    if (phoneExist) {
        return res.status(400).json({ message: "Phone already registerd with us" })
    }

    const hashPass = await bcrypt.hash(password, 10)

    await AuthModal.create({ name, email, phone, password: hashPass })

    res.json({ message: "User Register Success" })
})


exports.loginUser = asyncHandler(async (req, res) => {
    const { emailOrphone, password } = req.body

    if (!emailOrphone) {
        return res.status(400).json({ message: "Email/Phone and password are reqired " })
    }

    const result = AuthModal.findOne({
        $or: [{ email: emailOrphone }, { phone: emailOrphone }]
    })

    if (!result) {
        return res.status(400).json({ message: "user not found" })
    }

    const verifyPass = await bcrypt.compare(password, result.password)


    if (!verifyPass) {
        return res.status(400).json({ message: "Password dose not match" })
    }

    const generateOtp = Math.floor(1000 + Math.random() * 9000)

    console.log(generateOtp);


    const styleServer = `<html>
    <head>
        <style>
            body { font-family: 'Arial', sans-serif; background-color: #f4f4f4; color: #333; }
            h1 { color: #007BFF; }
            p { font-size: 16px; line-height: 1.6; color: #555; }
            .phone-number { background-color: #87CEEB; padding: 10px; display: inline-block; color:white; }
            .center-text { text-align: left; }
            .left-text { text-align: left; }
            .signature { margin-top: 20px; font-style: italic; }
        </style>
    </head>
    <body>
        <p class="left-text" style="font-weight: bold;">Hello, ${result.name},</p>
        <p class="center-text">
            Your OTP is ${generateOtp}
        </p>
        <p class="center-text signature">Best regards,<br>Our Company.</p>
    </body>
</html>`

    await sendEmail({
        to: result.email,
        html: styleServer,
        subject: `Verify OTP`
    })

    const otpExpiry = new Date(Date.now() + 2 * 60 * 1000)

    result.otp = generateOtp,
        req.otpExpiry = otpExpiry,
        await result.save()

    res.json({
        message: "OTP send to email. please verify to complete login"
    })

})

exports.verifyOpt = asyncHandler(async (req, res) => {
    const otp = req.body

    if (!otp) {
        return res.status(400).json({ message: "Otp is required" })
    }

    const result = AuthModal.findOne({ otp })

    if (!result) {
        return res.status(400).json({ message: "Invalid Opt" })
    }

    if (result.otpExpiry < Date.now()) {
        await AuthModal.updateOne(
            { _id: result._id },
            { $unset: { otp: 1, otpExpiry: 1 } }
        )
        return res.status(400).json({ message: "Otp has expired" })
    }

    await AuthModal.updateOne(
        { _id: result._id },
        { $unset: { otp: 1, otpExpiry: 1 } }
    )

    const token = jwt.sign({ userId: result._id }, process.env.JWT_KEY, { expiresIn: "7h" })
    res.cookie("AuthModal", token, { maxAge: 1000 * 60 * 60 * 24 * 7, httpOnly: true })

    res.json({
        message: "User login success",
        token,
        result: {
            name: result.name,
            email: result.email,
            phone: result.phone
        }
    })
})

exports.logoutUser = asyncHandler(async (req, res) => {
    res.clearCookie("AuthModal")
    res.json({ message: "User logout success" })
})


exports.requiestPasswordReset = asyncHandler(async (req, res) => {
    const { email } = req.body

    if (!email) {
        return res.status(400).json({ message: "Email is required" })
    }

    if (!validator.isEmail(email)) {
        return res.status(400).json({ message: "Please provide a valid email" })
    }

    const user = await AuthModal.findOne({ email })

    if (!user) {
        return res.status(400).json({ message: "User Not found" })
    }

    const generateOtp = Math.floor(1000 + Math.random() * 9000)
    const otpExpiry = new Date(Date.now() + 2 * 60 * 1000) //otp valid 2 minutes

    user.otp = generateOtp,
        user.otpExpiry = otpExpiry,
        await user.save()


    const styleServer = `<html>
        <head>
            <style>
                body { font-family: 'Arial', sans-serif; background-color: #f4f4f4; color: #333; }
                h1 { color: #007BFF; }
                p { font-size: 16px; line-height: 1.6; color: #555; }
                .phone-number { background-color: #87CEEB; padding: 10px; display: inline-block; color:white; }
                .center-text { text-align: left; }
                .left-text { text-align: left; }
                .signature { margin-top: 20px; font-style: italic; }
            </style>
        </head>
        <body>
            <p class="left-text" style="font-weight: bold;">Hello, ${user.name},</p>
            <p class="center-text">
                Your OTP is ${generateOtp}
            </p>
            <p class="center-text signature">Best regards,<br>Our Company.</p>
        </body>
    </html>`

    await sendEmail({
        to: user.email,
        html: styleServer,
        subject: "Password Reset Otp"
    })

    res.json({ message: "OTP sent to email. Please verify to reset your password." })

})

exports.verifyOtpForReset = asyncHandler(async (req, res) => {

    const { otp } = req.body

    if (!otp) {
        return res.status(400).json({ message: "Otp is required" })
    }

    const user = await AuthModal.findOne({ otp })

    if (!user) {
        return res.status(400).json({ message: "Invalid Otp" })
    }

    if (user.otpExpiry < Date.now()) {
        await AuthModal.updateOne({ _id: user._id }, { $unset: { otp: 1, otpExpiry: 1 } })
        return res.status(400).json({ message: "Otp has expired" })
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_KEY, { expiresIn: "15m" })// Token valid for 15 minutes

    res.json({ message: "OTP verified. You can now reset your password..", token })


})


exports.resetPassword = asyncHandler(async (req, res) => {
    const { token, newPassword } = req.body

    if (!token) {
        return res.status(400).json({ message: "Token is required" })
    }

    if (!newPassword) {
        return res.status(400).json({ message: "New Password is required" })
    }

    if (!validator.isStrongPassword(newPassword)) {
        return res.status(400).json({ message: "Please provide a strong password" })
    }

    try {
        const decode = jwt.verify(token, process.env.JWT_KEY)
        const userId = decode.userId

        const user = await AuthModal.findById(userId)

        if (!user) {
            return res.status(400).json({ message: "User not found" })
        }

        const hashPass = await bcrypt.hash(newPassword, 10)
        user.password = hashPass

        await AuthModal.updateOne(
            { _id: userId },
            { $unset: { otp: 1, otpExpiry: 1, isOtpVerified: 1, }, password: hashPass }

        )

        res.json({ message: "Password reset successful. You can now log in with your new password" })


    } catch (error) {
        return res.status(400).json({ message: "Invalid or expired token" })
    }

})

