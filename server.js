const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Razorpay = require("razorpay");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

// ✅ MongoDB Connection - FIXED: Using environment variable
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// ✅ Schemas
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  role: { type: String, enum: ["user", "delivery", "owner"], default: "user" },
  orders: [
    {
      products: [
        {
          name: String,
          price: Number,
          quantity: Number,
        },
      ],
      totalAmount: Number,
      status: { type: String, default: "pending" },
      otp: String,
      transactionId: String,
      createdAt: { type: Date, default: Date.now },
    },
  ],
  transactions: [
    {
      amount: Number,
      type: { type: String, enum: ["payment", "refund"] },
      status: { type: String, enum: ["success", "failed"] },
      createdAt: { type: Date, default: Date.now },
    },
  ],
});

const productSchema = new mongoose.Schema({
  name: String,
  description: String,
  price: Number,
  category: String,
  image: String,
});

const User = mongoose.model("User", userSchema);
const Product = mongoose.model("Product", productSchema);

// ✅ Razorpay Instance
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// ✅ Middleware: JWT verify
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Access token required" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }
    req.user = user;
    next();
  });
};

// ✅ User Register
app.post("/register", async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword, role: role || "user" });
    await user.save();

    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

// ✅ User Login
app.post("/login", async (req, res) => {
  try {
    const { email, password, role } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    if (role && user.role !== role) return res.status(400).json({ message: "Access denied for this role" });

    const token = jwt.sign({ userId: user._id, email: user.email, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: "24h",
    });

    res.json({ token, user: { id: user._id, username: user.username, email: user.email, role: user.role } });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

// ================== Delivery Boy Schema ==================
const deliveryBoySchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  phone: String,
  createdAt: { type: Date, default: Date.now }
});

const DeliveryBoy = mongoose.model("DeliveryBoy", deliveryBoySchema);

// ================== Delivery Boy Register ==================
app.post("/api/delivery/register", async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;

    // check existing
    const existing = await DeliveryBoy.findOne({ email });
    if (existing) {
      return res.status(400).json({ message: "Delivery boy already exists" });
    }

    // hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const newDeliveryBoy = new DeliveryBoy({
      name,
      email,
      password: hashedPassword,
      phone
    });

    await newDeliveryBoy.save();

    res.status(201).json({ message: "Delivery boy registered successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error", error });
  }
});

// ================== Delivery Boy Login ==================
app.post("/api/delivery/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const deliveryBoy = await DeliveryBoy.findOne({ email });
    if (!deliveryBoy) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, deliveryBoy.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: deliveryBoy._id, role: "delivery" },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({ token, deliveryBoy });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

// ================== Owner Schema ==================
const ownerSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true },
  password: String,
  createdAt: { type: Date, default: Date.now }
});

const Owner = mongoose.model("Owner", ownerSchema);

// ✅ Owner Login (hardcoded, separate collection)
app.post("/owner/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Hardcoded check
    if (email === "am@gmail.com" && password === "12345") {

      // Check in owners collection
      let owner = await Owner.findOne({ email });
      if (!owner) {
        // Agar owner nahi hai to create
        owner = new Owner({
          username: "Owner",
          email,
          password: await bcrypt.hash(password, 10)
        });
        await owner.save();
      }

      // JWT token generate
      const token = jwt.sign(
        { userId: owner._id, email: owner.email, role: "owner" },
        process.env.JWT_SECRET,
        { expiresIn: "24h" }
      );

      res.json({ token, user: { id: owner._id, username: owner.username, email: owner.email, role: "owner" } });
    } else {
      res.status(400).json({ message: "Invalid owner credentials" });
    }
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

// ✅ Products Routes
app.get("/products", async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

app.post("/products", async (req, res) => {
  try {
    const { name, description, price, category, image } = req.body;
    const product = new Product({ name, description, price, category, image });
    await product.save();
    res.status(201).json({ message: "Product added successfully", product });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

// ✅ Add Sample Products (Safe Version - No Duplicates)
app.post("/add-sample-products", async (req, res) => {
  try {
    const sampleProducts = [
      { name: "North Indian Thali", description: "Full meal", price: 250, category: "thali", image: "https://via.placeholder.com/150" },
      { name: "South Indian Thali", description: "Rice + Sambar", price: 220, category: "thali", image: "https://via.placeholder.com/150" },
      { name: "Punjabi Thali", description: "Makki di Roti + Saag", price: 280, category: "thali", image: "https://via.placeholder.com/150" },
    ];

    let inserted = [];

    for (let product of sampleProducts) {
      const existing = await Product.findOne({ name: product.name });
      if (!existing) {
        const newProduct = new Product(product);
        await newProduct.save();
        inserted.push(newProduct);
      }
    }

    if (inserted.length > 0) {
      res.json({ message: "Sample products added successfully", inserted });
    } else {
      res.json({ message: "All sample products already exist, nothing added." });
    }
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

// ✅ Root Route
app.get("/", (req, res) => {
  res.send("✅ Backend is running successfully 🚀");
});

// ✅ Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
