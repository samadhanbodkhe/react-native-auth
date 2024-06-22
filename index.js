const express = require("express")
const mongoose = require("mongoose")
const cors = require("cors")
const cookieParser = require("cookie-parser")
require("dotenv").config({ path: "./.env" })
require("./jobs/otpCleanUp")

const app = express()

app.use(express.json())
app.use(cors({
    origin: "http://localhost:5173",
    credentials: true
}))
app.use(cookieParser())


app.use("./api/auth", require("./routes/authRoute"))

app.use("*", (req, res) => {
    res.status(400).json({ message: "Resource not found" })
})

app.use((err, req, res, next) => {
    console.log(err)
    res.status(500).json({ message: err.message || "Something went wrong" })
})

mongoose.connect(process.env.MONGO_URL)

mongoose.connection.once("open", () => {
    console.log("MONGO CONNECTED")
    app.listen(process.env.PORT, console.log("SERVER RUNNING"))
})