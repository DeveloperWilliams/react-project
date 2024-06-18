import express from "express";
import dotenv from "dotenv";
import helmet from "helmet";
import morgan from "morgan";
import cors from "cors";
import { body, validationResult } from "express-validator";
import mongoose from "mongoose";
import rateLimit from "express-rate-limit";
import bcrypt from "bcrypt";

//Declaring DotEnv
dotenv.config();

const app = express();

const Limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too Many Requsts from this IP",
});

//middleware
app.use(cors());
app.use(express.json());
app.use(helmet());
app.use(morgan("common"));
app.use(Limiter);

try {
  mongoose.connect("mongodb://127.0.0.1:27017/testing-login");
  console.log("Connected to Database");
} catch (error) {
  console.log(error);
}

const userSchema = new mongoose.Schema({
  Username: String,
  Email: String,
  Password: String,
});

const model = mongoose.model("User", userSchema);

app.post(
  "/signup",
  [
    body("Username").notEmpty().withMessage("Username Cannot be Empty"),
    body("Email").isEmail().withMessage("Enter a valid Email Address"),
    body("Password")
      .isLength({ min: 7 })
      .withMessage("A password must be atleast 8 characters")
      .isStrongPassword()
      .withMessage("Please Enter a strong password"),
  ],
  async (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array() });
    }

    const { Username, Email, Password } = req.body;

    try {
      const checkUser = await model.findOne({ Email });
      if (checkUser) {
        return res.status(400).json("Email Already Registered");
      }
      const hashedPassword = await bcrypt.hash(Password, 10);

      const newUser = model({
        Username: Username,
        Email: Email,
        Password: hashedPassword,
      });
      newUser.save();
      return res.status(201).json(newUser);
    } catch (error) {
      return res.status(500).json("Internal Servor Error");
    }
  }
);

app.post(
  "/login",
  [
    body("Email")
      .isEmail()
      .withMessage("Input a Valid Email")
      .notEmpty()
      .withMessage("Email Cannot be Empty"),
    body("Password").notEmpty().withMessage("Password cannot be Empty"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty) {
      return res.status(400).json({message: "There was an Error"});
    }

    try {
      const { Email, Password } = req.body;

      const checkUser = await model.findOne({ Email });

      if (!checkUser) {
        return res.status(404).json({message:"Email Not Regisred"});
      }

      //Retain Await - Don't Touch
      const passwordMatCh = await bcrypt.compare(Password, checkUser.Password);

      if (!passwordMatCh) {
        return res.status(401).json({message: "Incorrect Password"});
      }

      res.status(200).json({message: "Login Succesfull"});
    } catch (error) {
      res.status(500).json({message: "Internal Server Error"});
    }
  }
);

const PORT = 8080;
app.listen(PORT, () => {
  console.log(`Server running on PORT Number ${PORT}`);
});
