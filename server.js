const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});


db.connect(err => {
  if (err) {
    console.error("❌ MySQL Connection Error:", err.message);
    console.error("Please ensure your MySQL server is running and the credentials in .env are correct.");
    return;
  }
  console.log("✅ MySQL connected to database:", process.env.DB_NAME);
});
// Temporary route to create users table
app.get("/create-users-table", (req, res) => {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      aadhaar VARCHAR(12) UNIQUE NOT NULL
    );
  `;
  db.query(createTableQuery, (err, result) => {
    if (err) {
      return res.status(500).json({ error: "Failed to create table", details: err.message });
    }
    res.json({ success: true, message: "Users table created successfully" });
  });
});

app.post("/signup", async (req, res) => {
  const { username, password, aadhaar } = req.body;
  if (!username || !password || !aadhaar) {
    return res.status(400).json({ error: "All fields are required" });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query(
      "INSERT INTO users (username, password, aadhaar) VALUES (?, ?, ?)",
      [username, hashedPassword, aadhaar],
      (err, result) => {
        if (err) {
          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ error: "User or Aadhaar already exists" });
          }
          return res.status(500).json({ error: "Database error during signup" });
        }
        res.status(201).json({ success: true, message: "User registered successfully" });
      }
    );
  } catch (e) {
    res.status(500).json({ error: "Server error during signup" });
  }
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, results) => {
      if (err) {
        return res.status(500).json({ error: "Database query failed" });
      }
      if (results.length === 0) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const user = results[0];
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const token = jwt.sign(
        { id: user.id, username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );
      
      res.json({ success: true, message: "Login successful", token: token });
    }
  );
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});