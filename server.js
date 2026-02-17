const jwt = require("jsonwebtoken");
const SECRET_KEY = "smartfoodsecret";
const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const admin = require("firebase-admin");
const cors = require("cors");
const PORT = process.env.PORT || 3000;


const app = express();
app.use(bodyParser.json());
app.use(cors());
app.use(express.static("public"));


const serviceAccount = require("./serviceAccountKey.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

app.get("/", (req, res) => {
  res.send("Smart Food Server with Firestore Running");
});
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if email already exists
    const userRef = db.collection("users").doc(email);
    const doc = await userRef.get();

    if (doc.exists) {
      return res.status(400).send("Email already exists");
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Store user in Firestore
    await userRef.set({
      email: email,
      password: hashedPassword
    });

    res.send("User Registered Successfully");

  } catch (error) {
    res.status(500).send(error.message);
  }
});
app.post("/signin", async (req, res) => {
  const { email, password } = req.body;

  try {
    const userRef = db.collection("users").doc(email);
    const doc = await userRef.get();

    if (!doc.exists) {
      return res.status(400).send("User not found");
    }

    const userData = doc.data();

    const isMatch = await bcrypt.compare(password, userData.password);

    if (!isMatch) {
      return res.status(400).send("Invalid Password");
    }

    const token = jwt.sign({ email: email }, SECRET_KEY, { expiresIn: "1h" });
res.json({ message: "Login Successful", token: token });



  } catch (error) {
    res.status(500).send(error.message);
  }
});
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    return res.status(403).send("Token required");
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).send("Invalid Token");
    }

    req.user = decoded;
    next();
  });
}
app.get("/dashboard-data", verifyToken, async (req, res) => {
  try {
    const snapshot = await db.collection("foods").get();

    const foodItems = [];

    snapshot.forEach(doc => {
  const data = doc.data();

  if (data && data.name) {
    foodItems.push({
      name: data.name,
      price: data.price,
      quantity: data.quantity
    });
  }
});


    res.json({
      message: "Welcome " + req.user.email,
      foodItems: foodItems
    });

  } catch (error) {
    res.status(500).send("Error loading food data");
  }
});


app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

