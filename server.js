require("dotenv").config();
const express = require("express");
const mse = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path");

const app = express();
const port = 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// DB Connection
mse.connect(process.env.DB_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log("DB Error:", err));


// USER SCHEMA (UPDATED)
const userSchema = new mse.Schema({
  username: { type: String, required: true, unique: true },
  profileName: { type: String, required: true },   // 🔥 NEW FIELD
  hashedPassword: { type: String, required: true }
});

const User = mse.model("User", userSchema);


// PASSWORD VAULT SCHEMA
const vaultSchema = new mse.Schema({
  userId: { type: mse.Schema.Types.ObjectId, ref: "User" },
  site: String,
  username: String,
  password: String
});

const Vault = mse.model("Vault", vaultSchema);


// AUTH MIDDLEWARE
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
}


// REGISTER ROUTE (UPDATED)
app.post("/register", async (req, res) => {
  const { username, password, profileName } = req.body;

  if (!username || !password || !profileName) {
    return res.status(400).json({ message: "All fields are required" });
  }

  const exists = await User.findOne({ username });
  if (exists) return res.status(400).json({ message: "Username already exists" });

  const hash = await bcrypt.hash(password, 10);
  const newUser = new User({ username, profileName, hashedPassword: hash });
  await newUser.save();

  res.status(201).json({ message: "Registered successfully!" });
});


// LOGIN ROUTE (UPDATED)
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });
  if (!user) return res.status(404).json({ message: "User not found" });

  const correct = await bcrypt.compare(password, user.hashedPassword);
  if (!correct) return res.status(400).json({ message: "Wrong password" });

  const token = jwt.sign(
    { id: user._id, profileName: user.profileName,username: user.username },  // 🔥 include profileName
    process.env.JWT_SECRET
  );

  res.json({
    message: "Login success",
    token,
    profileName: user.profileName // 🔥 return it to frontend
  });
});


// ADD PASSWORD
app.post("/add-password", auth, async (req, res) => {
  const { site, username, password } = req.body;

  const newPass = new Vault({
    userId: req.user.id,
    site,
    username,
    password
  });

  await newPass.save();
  res.json({ message: "Password saved!" });
});


// GET PASSWORDS
app.get("/get-passwords", auth, async (req, res) => {
  const data = await Vault.find({ userId: req.user.id });
  res.json(data);
});


// DEFAULT ROUTE - LOAD FRONTEND
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});


// START SERVER
app.listen(process.env.PORT || PORT, () => {
    console.log("Server is running...");
});
