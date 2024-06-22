const corn = require("node-cron")
const auth = require("../modal/AuthModal") //Adjust the path as per your project structure


corn.schedule(`*/2 * * * *`, async () => {
    try {
        // Update documents to unset otp and otpExpiry fields
        await auth.updateMany(
            { otp: { $exists: true }, otpExpiry: { $exists: true } },// Filter to match documents with otp and otpExpiry
            { $unset: { otp: '', otpExpiry: '' } }// Unset otp and otpExpiry fields
        )
        console.log("otp and otpExpiry fields cleaned up successfully.")
    } catch (error) {
        console.error("Error cleaning up otp and otpExpiry fields:", error.message)
    }
}, {
    scheduled: true,
    timezone: "Asia/Kolkata"// Adjust timezone as per your server's timezone
})