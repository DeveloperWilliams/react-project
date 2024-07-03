import express from "express";
import dotenv from "dotenv";
import helmet from "helmet";
import morgan from "morgan";
import cors from "cors";
import { body, validationResult } from "express-validator";
import mongoose from "mongoose";
import rateLimit from "express-rate-limit";
import bcrypt from "bcrypt";

// Load environment variables from .env file
dotenv.config();

const app = express();

// Rate Limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: "Too Many Requests from this IP",
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(helmet());
app.use(morgan("common"));
app.use(limiter);

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI || "mongodb://127.0.0.1:27017/testing-login", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("Connected to Database"))
.catch((error) => console.error("Database connection error:", error));

// User Schema and Model
const userSchema = new mongoose.Schema({
  Username: { type: String, required: true },
  Email: { type: String, required: true, unique: true },
  Password: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);

// Signup Route
app.post(
  "/signup",
  [
    body("Username").notEmpty().withMessage("Username Cannot be Empty"),
    body("Email").isEmail().withMessage("Enter a valid Email Address"),
    body("Password")
      .isLength({ min: 8 }).withMessage("Password must be at least 8 characters")
      .isStrongPassword().withMessage("Please enter a strong password"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { Username, Email, Password } = req.body;

    try {
      const existingUser = await User.findOne({ Email });
      if (existingUser) {
        return res.status(400).json({ message: "Email already registered" });
      }

      const hashedPassword = await bcrypt.hash(Password, 10);
      const newUser = new User({ Username, Email, Password: hashedPassword });
      await newUser.save();

      return res.status(201).json({ message: "User created successfully", user: newUser });
    } catch (error) {
      return res.status(500).json({ message: "Internal Server Error", error });
    }
  }
);

// Login Route
app.post(
  "/login",
  [
    body("Email").isEmail().withMessage("Enter a valid Email").notEmpty().withMessage("Email cannot be empty"),
    body("Password").notEmpty().withMessage("Password cannot be empty"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { Email, Password } = req.body;

    try {
      const user = await User.findOne({ Email });
      if (!user) {
        return res.status(404).json({ message: "Email not registered" });
      }

      const isPasswordMatch = await bcrypt.compare(Password, user.Password);
      if (!isPasswordMatch) {
        return res.status(401).json({ message: "Incorrect password" });
      }

      return res.status(200).json({ message: "Login successful" });
    } catch (error) {
      return res.status(500).json({ message: "Internal Server Error", error });
    }
  }
);

// Start Server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server running on PORT ${PORT}`);
});
