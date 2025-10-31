// ---------- FGM ADMIN BACKEND (with Auth, Event Details, About) ----------
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const cors = require("cors");
const path = require("path");
const bodyParser = require("body-parser");
const multer = require("multer"); // For file uploads
const fs = require("fs"); // For file system operations
const jwt = require("jsonwebtoken"); // 🌟 For authentication
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

// --- Serve frontend files AND the uploads folder ---
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "public/uploads")));

// --- Database Connection ---
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) {
    console.error("❌ DB Connection Failed:", err);
  } else {
    console.log("✅ Connected to Clever Cloud MySQL!");
  }
});

// --- Multer Configuration (File Uploads) ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Ensure the uploads directory exists
    const uploadDir = 'public/uploads/';
    if (!fs.existsSync(uploadDir)){
        fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});
const upload = multer({ storage: storage });

// --- Helper Function to Get a Record (for deleting/editing images) ---
const getRecordById = (table, id) => {
  return new Promise((resolve, reject) => {
    db.query(`SELECT * FROM ${table} WHERE id = ?`, [id], (err, results) => {
      if (err) return reject(err);
      resolve(results[0]);
    });
  });
};

// --- Helper Function to Delete a File ---
const deleteFile = (filePath) => {
  if (!filePath) return;
  // Check if filePath starts with 'uploads/'
  if (!filePath.startsWith("uploads/")) {
    console.warn(
      `Skipping delete: File path '${filePath}' is not in uploads folder.`
    );
    return;
  }
  const actualPath = path.join(__dirname, "public", filePath);
  fs.unlink(actualPath, (err) => {
    if (err) {
      console.warn(`Could not delete file ${actualPath}:`, err.message);
    } else {
      console.log(`Deleted file ${actualPath}`);
    }
  });
};

// --- 🌟 JWT Secret & Auth Middleware 🌟 ---
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error("FATAL ERROR: JWT_SECRET is not defined in .env file.");
    process.exit(1);
}

const verifyToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

  if (token == null) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.warn("JWT Verification failed:", err.message);
      return res.status(403).json({ error: "Invalid token." });
    }
    req.user = user; // Add user payload to request
    next(); // Proceed to the protected route
  });
};

// --- 🌟 Login (Updated to generate JWT) 🌟 ---
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required." });
  }
  db.query("SELECT * FROM admin WHERE email = ?", [email], async (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (results.length === 0)
      return res.status(401).json({ error: "Invalid email or password" });

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match)
      return res.status(401).json({ error: "Invalid email or password" });

    // --- Generate JWT Token ---
    const tokenPayload = { id: user.id, email: user.email };
    // Token expires in 1 day
    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: "1d" });

    // Send token back to the client
    res.json({ success: true, message: "Login successful", token: token });
  });
});

// --- 🌟 EVENTS API (CRUD - UPDATED FOR DETAILS) 🌟 ---

// GET All Events (for grid) - Public, no auth
app.get("/api/events", (req, res) => {
  // Only select data needed for the grid view
  db.query(
    "SELECT id, title, subtitle, description, imageUrl FROM events ORDER BY id DESC",
    (err, rows) => {
      if (err) return res.status(500).json({ error: "Failed to fetch events" });
      res.json(rows);
    }
  );
});

// GET Single Event (for detail page) - Public, no auth
app.get("/api/events/:id", (req, res) => {
  const { id } = req.params;
  db.query("SELECT * FROM events WHERE id = ?", [id], (err, results) => {
    if (err) {
      console.error("❌ SQL Error (GET Event ID):", err);
      return res.status(500).json({ error: "Failed to fetch event details" });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: "Event not found" });
    }
    res.json(results[0]); // Send the full single event object
  });
});

// POST Event (Updated for multiple files and new fields) - Protected
app.post(
  "/api/events",
  verifyToken, // 🌟 Auth enabled
  upload.fields([
    { name: "image", maxCount: 1 }, // Grid image
    { name: "detailImage", maxCount: 1 }, // Detail page image
  ]),
  (req, res) => {
    const { title, subtitle, description, fullDescription, registrationNote } =
      req.body;

    const imageUrl = req.files["image"]
      ? `uploads/${req.files["image"][0].filename}`
      : null;
    const detailImageUrl = req.files["detailImage"]
      ? `uploads/${req.files["detailImage"][0].filename}`
      : null;

    const sql = `INSERT INTO events 
            (title, subtitle, description, imageUrl, fullDescription, registrationNote, detailImageUrl) 
            VALUES (?, ?, ?, ?, ?, ?, ?)`;

    const params = [
      title,
      subtitle,
      description,
      imageUrl,
      fullDescription,
      registrationNote,
      detailImageUrl,
    ];

    db.query(sql, params, (err, result) => {
      if (err) {
        console.error("❌ SQL INSERT Error (Events):", err);
        return res.status(500).json({ error: "Failed to add event" });
      }
      res.json({ success: true, id: result.insertId });
    });
  }
);

// PUT Event (Updated for multiple files and new fields) - Protected
app.put(
  "/api/events/:id",
  verifyToken, // 🌟 Auth enabled
  upload.fields([
    { name: "image", maxCount: 1 },
    { name: "detailImage", maxCount: 1 },
  ]),
  async (req, res) => {
    const { id } = req.params;
    const {
      title,
      subtitle,
      description,
      fullDescription,
      registrationNote,
      existingImageUrl,
      existingDetailImageUrl,
    } = req.body;

    let imageUrl = existingImageUrl || null;
    let detailImageUrl = existingDetailImageUrl || null;

    try {
      const oldRecord = await getRecordById("events", id);

      // Check for new grid image
      if (req.files["image"]) {
        if (oldRecord && oldRecord.imageUrl) {
          deleteFile(oldRecord.imageUrl);
        }
        imageUrl = `uploads/${req.files["image"][0].filename}`;
      }

      // Check for new detail image
      if (req.files["detailImage"]) {
        if (oldRecord && oldRecord.detailImageUrl) {
          deleteFile(oldRecord.detailImageUrl);
        }
        detailImageUrl = `uploads/${req.files["detailImage"][0].filename}`;
      }

      const sql = `UPDATE events SET 
                title = ?, subtitle = ?, description = ?, imageUrl = ?,
                fullDescription = ?, registrationNote = ?, detailImageUrl = ?
                WHERE id = ?`;

      const params = [
        title,
        subtitle,
        description,
        imageUrl,
        fullDescription,
        registrationNote,
        detailImageUrl,
        id,
      ];

      db.query(sql, params, (err, result) => {
        if (err) {
          console.error("❌ SQL UPDATE Error (Events):", err);
          return res.status(500).json({ error: "Failed to update event" });
        }
        res.json({ success: true, message: "Event updated" });
      });
    } catch (err) {
      console.error("❌ Server Error (PUT Event):", err);
      res.status(500).json({ error: "Server error during update." });
    }
  }
);

// DELETE Event (Updated to delete both images) - Protected
app.delete("/api/events/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const record = await getRecordById("events", id);
    // Delete both images if they exist
    if (record) {
      if (record.imageUrl) deleteFile(record.imageUrl);
      if (record.detailImageUrl) deleteFile(record.detailImageUrl);
    }
    db.query("DELETE FROM events WHERE id = ?", [id], (err, result) => {
      if (err) {
        console.error("❌ SQL DELETE Error (Events):", err);
        return res.status(500).json({ error: "Failed to delete event" });
      }
      res.json({ success: true, message: "Event deleted" });
    });
  } catch (err) {
    console.error("❌ Server Error (DELETE Event):", err);
    res.status(500).json({ error: "Server error during delete." });
  }
});

// --- 🌟 LOCATIONS API (CRUD - NOW SECURED) 🌟 ---

// GET All Locations (for grid) - Public, no auth
app.get("/api/locations", (req, res) => {
  db.query(
    "SELECT id, title, subtitle, description, imageUrl FROM locations ORDER BY id DESC",
    (err, rows) => {
      if (err)
        return res.status(500).json({ error: "Failed to fetch locations" });
      res.json(rows);
    }
  );
});

// GET Single Location (for detail page) - Public, no auth
app.get("/api/locations/:id", (req, res) => {
  const { id } = req.params;
  db.query("SELECT * FROM locations WHERE id = ?", [id], (err, results) => {
    if (err) {
      console.error("❌ SQL Error (GET Location ID):", err);
      return res.status(500).json({ error: "Failed to fetch location details" });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: "Location not found" });
    }
    res.json(results[0]);
  });
});

// POST Location - Protected
app.post(
  "/api/locations",
  verifyToken, // 🌟 Auth enabled
  upload.fields([
    { name: "image", maxCount: 1 },
    { name: "detailImage", maxCount: 1 },
  ]),
  (req, res) => {
    const {
      title,
      subtitle,
      description,
      pastorName,
      phone,
      email,
      address,
      mailingAddress,
      googleMapEmbed,
    } = req.body;
    const imageUrl = req.files["image"]
      ? `uploads/${req.files["image"][0].filename}`
      : null;
    const detailImageUrl = req.files["detailImage"]
      ? `uploads/${req.files["detailImage"][0].filename}`
      : null;
    const sql = `INSERT INTO locations 
            (title, subtitle, description, imageUrl, 
             pastorName, phone, email, address, mailingAddress, googleMapEmbed, detailImageUrl) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    const params = [
      title,
      subtitle,
      description,
      imageUrl,
      pastorName,
      phone, // 🌟 FIXED (removed the extra '.')
      email,
      address,
      mailingAddress,
      googleMapEmbed,
      detailImageUrl,
    ];
    db.query(sql, params, (err, result) => {
      if (err) {
        console.error("❌ SQL INSERT Error (Locations):", err);
        return res.status(500).json({ error: "Failed to add location" });
      }
      res.json({ success: true, id: result.insertId });
    });
  }
);

// PUT Location - Protected
app.put(
  "/api/locations/:id",
  verifyToken, // 🌟 Auth enabled
  upload.fields([
    { name: "image", maxCount: 1 },
    { name: "detailImage", maxCount: 1 },
  ]),
  async (req, res) => {
    const { id } = req.params;
    const {
      title,
      subtitle,
      description,
      pastorName,
      phone,
      email,
      address,
      mailingAddress,
      googleMapEmbed,
      existingImageUrl,
      existingDetailImageUrl,
    } = req.body;
    let imageUrl = existingImageUrl || null;
    let detailImageUrl = existingDetailImageUrl || null;
    
    // 🌟 FIXED (was 'true {')
    try {
      const oldRecord = await getRecordById("locations", id);
      if (req.files["image"]) {
        if (oldRecord && oldRecord.imageUrl) {
          deleteFile(oldRecord.imageUrl);
        }
        imageUrl = `uploads/${req.files["image"][0].filename}`;
      }
      if (req.files["detailImage"]) {
        if (oldRecord && oldRecord.detailImageUrl) {
          deleteFile(oldRecord.detailImageUrl);
        }
        detailImageUrl = `uploads/${req.files["detailImage"][0].filename}`;
      }
      const sql = `UPDATE locations SET 
                title = ?, subtitle = ?, description = ?, imageUrl = ?,
                pastorName = ?, phone = ?, email = ?, address = ?, mailingAddress = ?, googleMapEmbed = ?, detailImageUrl = ?
                WHERE id = ?`;
      const params = [
        title,
        subtitle,
        description,
        imageUrl,
        pastorName,
        phone,
        email,
        address,
        mailingAddress,
        googleMapEmbed,
        detailImageUrl,
        id,
      ];
      db.query(sql, params, (err, result) => {
        if (err) {
          console.error("❌ SQL UPDATE Error (Locations):", err);
          return res.status(500).json({ error: "Failed to update location" });
        }
        res.json({ success: true, message: "Location updated" });
      });
    } catch (err) {
      console.error("❌ Server Error (PUT Location):", err);
      res.status(500).json({ error: "Server error during update." });
    }
  }
);

// DELETE Location - Protected
app.delete("/api/locations/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const record = await getRecordById("locations", id);
    if (record) {
      if (record.imageUrl) deleteFile(record.imageUrl);
      if (record.detailImageUrl) deleteFile(record.detailImageUrl);
    }
    db.query("DELETE FROM locations WHERE id = ?", [id], (err, result) => {
      if (err) {
        console.error("❌ SQL DELETE Error (Locations):", err);
        return res.status(500).json({ error: "Failed to delete location" });
      }
      res.json({ success: true, message: "Location deleted" });
    });
  } catch (err) {
    console.error("❌ Server Error (DELETE Location):", err);
    res.status(500).json({ error: "Server error during delete." });
  }
});

// --- 🌟 GALLERY API (CRUD - NOW SECURED) 🌟 ---

// GET All Gallery - Public, no auth
app.get("/api/gallery", (req, res) => {
  // 🌟 FIXED (removed 'G')
  db.query("SELECT * FROM gallery ORDER BY id DESC", (err, rows) => {
    if (err) return res.status(500).json({ error: "Failed to fetch gallery" });
    res.json(rows);
  });
});

// POST Gallery - Protected
app.post("/api/gallery", verifyToken, upload.single("image"), (req, res) => {
  const { category } = req.body;
  const imageUrl = req.file ? `uploads/${req.file.filename}` : null;
  if (!imageUrl) {
    return res.status(400).json({ error: "Image file is required." });
  }
  db.query(
    "INSERT INTO gallery (imageUrl, category) VALUES (?, ?)",
    [imageUrl, category],
    // 🌟 FIXED (removed 'warning')
    (err, result) => {
      if (err) {
        console.error("❌ SQL INSERT Error (Gallery):", err);
        return res.status(500).json({ error: "Failed to add photo" });
      }
      res.json({ success: true, id: result.insertId });
    }
  );
});

// DELETE Gallery - Protected
app.delete("/api/gallery/:id", verifyToken, async (req, res) => {
  // 🌟 FIXED (removed 'A')
  const { id } = req.params;
  try {
    const record = await getRecordById("gallery", id);
    if (record && record.imageUrl) {
      deleteFile(record.imageUrl);
    }
    db.query("DELETE FROM gallery WHERE id = ?", [id], (err, result) => {
      // 🌟 FIXED (removed 'warning')
      if (err) {
        console.error("❌ SQL DELETE Error (Gallery):", err);
        return res.status(500).json({ error: "Failed to delete photo" });
      }
      res.json({ success: true, message: "Photo deleted" });
    });
  } catch (err) {
    console.error("❌ Server Error (DELETE Gallery):", err);
    // 🌟 FIXED (removed 'Look' and the browser log message)
    res.status(500).json({ error: "Server error during delete." });
  }
});

// --- 🌟 NEW: ABOUT PAGE API 🌟 ---

// GET About Content - Public, no auth
app.get("/api/about", (req, res) => {
  db.query("SELECT * FROM about_content WHERE id = 1", (err, results) => {
    if (err)
      return res.status(500).json({ error: "Failed to fetch about content" });
    if (results.length === 0) {
      return res.status(404).json({ error: "About content not found." });
    }
    res.json(results[0]);
  });
});

// PUT About Content - Protected
app.put("/api/about", verifyToken, (req, res) => {
  const { ourMission, ourStory } = req.body;
  
  if (ourMission === undefined || ourStory === undefined) {
      return res.status(400).json({ error: "Both ourMission and ourStory fields are required."});
  }

  db.query(
    "UPDATE about_content SET ourMission = ?, ourStory = ? WHERE id = 1",
    [ourMission, ourStory],
    (err, result) => {
      if (err) {
        console.error("❌ SQL UPDATE Error (About):", err);
        // 🌟 FIXED (removed 'Warning')
        return res.status(500).json({ error: "Failed to update about content" });
      }
      res.json({ success: true, message: "About page updated" });
    }
  );
});

// --- Server ---
const PORT = process.env.PORT || 5000; // Use port from .env or fallback to 5000
app.listen(PORT, () =>
  console.log(`🚀 Server running at http://localhost:${PORT}`)
);