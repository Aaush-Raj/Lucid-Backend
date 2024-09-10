// Importing necessary modules
import mongoose from "mongoose";
import dotenv from "dotenv";
import express from "express";
import connectDB from "./db/index.js";
import jwt from "jsonwebtoken";
import cors from "cors"; 

import bcrypt from "bcrypt";
import { z } from "zod"; 

dotenv.config({ path: "./env" });

const jwtPswd = process.env.JWT_SECRET || "test1234";
const app = express();

// Connect to the database
connectDB()
  .then(() => {
    app.listen(process.env.PORT || 8000, () => {
      console.log(`Server is running at port ${process.env.PORT}`);
    });
  })
  .catch((error) => {
    console.log("MONGO DB CONNECTION FAILED :", error);
  });

const User = mongoose.model("Users", {
  username: String,
  password: String,
  email: String,
});

// Zod schemas for request validation
const signUpSchema = z.object({
  username: z.string().min(1, "Username is required"),
  password: z.string().min(6, "Password must be at least 6 characters long"),
  email: z.string().email("Invalid email address"),
});

const signInSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z.string().min(6, "Password must be at least 6 characters long"),
});

app.use(cors()); // Enable CORS for all routes
app.use(express.json());
const isAdmin = true
const adminKey = "ABCD11"

function checkAdmin(req, res, next){
  let key=  req.headers.key
  if(adminKey === key){
    console.log("USER IS A ADMIN")
    next()
    return;
  }

  return res.status(401).json({success:false,message:"USER IS NOT ADMIN.."})
}



app.get("/isAdmin",checkAdmin,async (req,res)=>{

  let data = await User.find({}).select('email');
  console.log("________________-")
  console.log(data)
  return res.json({success:true,message:"USER IS ADMIN..",data:data})
  // res.status(200).json({success:true,message:"USER IS ADMIN.."})
  
})

app.post("/sign-up", async function (req, res) {
  // Validate the request body using Zod
  const result = signUpSchema.safeParse(req.body);
  if (!result.success) {
    console.log(result.error.errors)
    return res.status(400).json({ success: false, errors: result.error.errors });
  }

  try {
    const { username, password, email } = result.data;

    let alreadyUser = await User.findOne({ email: email });
    if (alreadyUser) {
      return res
        .status(400)
        .json({ success: false, message: "Email already in use!" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      username: username,
      password: hashedPassword,
      email: email,
    });
    await user.save();

    return res.status(201).json({
      success: true,
      message: "User created successfully!",
      user: { username, email },
    });
  } catch (error) {
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
});

app.post("/sign-in", async function (req, res) {
  // Validate the request body using Zod
  const result = signInSchema.safeParse(req.body);
  if (!result.success) {
    return res.status(400).json({ success: false, errors: result.error.errors });
  }

  const { email, password } = result.data;
  try {
    const user = await User.findOne({ email: email });
    if (!user) {
      return res
        .status(403)
        .json({ message: "User does not exist. Please create an account first." });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(403).json({ message: "Incorrect password." });
    }

    let token = jwt.sign({ email: email }, jwtPswd, { expiresIn: "4h" });
    return res.status(201).json({
      success: true,
      message: "User login successful!",
      token: token,
    });
  } catch (error) {
    return res.status(500).json({ message: "Internal server error" });
  }
});
