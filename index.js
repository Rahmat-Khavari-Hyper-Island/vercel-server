const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

// Test the database connection
pool.query("SELECT NOW()", (err, res) => {
  if (err) {
    console.error("Error connecting to the database:", err);
  } else {
    console.log("Connected to the database:", res.rows[0].now);
  }
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ message: "Authorization header is missing or malformed" });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error(err);
      return res.status(401).json({ message: "Invalid token" });
    }
    req.user = decoded;
    next();
  });
};

// Database queries
const query = async (sql, params) => {
  try {
    const result = await pool.query(sql, params);
    return result;
  } catch (error) {
    console.error("Database query error:", error);
    throw error;
  }
};

// GET Request
app.get("/users", async (req, res) => {
  try {
    const result = await query(
      "SELECT user_id, username, first_name, last_name FROM users"
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: "Error fetching users" });
  }
});

//POST Request
app.post("/signup", async (req, res) => {
  const { username, email, password, first_name, last_name } = req.body;

  // Validate required fields
  if (!username || !email || !password || !first_name || !last_name) {
    return res.status(400).json({
      message:
        "Please provide username, email, password, first name, and last name",
    });
  }

  try {
    // Check if the username or email is already in use
    const existingUser = await pool.query(
      "SELECT * FROM users WHERE username = $1 OR email = $2",
      [username, email]
    );
    if (existingUser.rows.length > 0) {
      return res
        .status(409)
        .json({ message: "Username or email already exists" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 15);

    // Insert the user into the database
    const query =
      "INSERT INTO users (username, email, password_hash, first_name, last_name) VALUES ($1, $2, $3, $4, $5) RETURNING user_id";
    const values = [username, email, hashedPassword, first_name, last_name];
    const result = await pool.query(query, values);

    // Retrieve the user_id from the result
    const user_id = result.rows[0].user_id;

    // Generate JWT token
    const token = jwt.sign({ user_id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    // Send a success response with the token
    res.status(201).json({ token });
  } catch (error) {
    // Handle errors
    console.error("Error creating user:", error);
    res
      .status(500)
      .json({ message: "An error occurred while creating the user" });
  }
});

app.get("/messages", async (req, res) => {
  pool.query(
    "SELECT * FROM messages ORDER BY timestamp DESC",
    (err, result) => {
      if (err) {
        console.error("Error executing query:", err);
        res.status(500).send("Error executing query");
      } else {
        res.json(result.rows);
      }
    }
  );
});

//POST Request
app.post("/create_message", verifyToken, async (req, res) => {
  const { message_text } = req.body;
  const user_id = req.user.user_id;

  // Validate required fields
  if (!message_text) {
    return res.status(400).json({ message: "Please provide message_text" });
  }

  try {
    // Insert the message into the database
    const query =
      "INSERT INTO messages (user_id, message_text) VALUES ($1, $2) RETURNING message_id"; // Changed table name to messages
    const values = [user_id, message_text];
    const result = await pool.query(query, values);

    // Send a success response with the newly created message's ID
    res.status(201).json({ messageId: result.rows[0].message_id });
  } catch (error) {
    // Handle errors
    console.error("Error creating message:", error);
    res
      .status(500)
      .json({ message: "An error occurred while creating the message" });
  }
});

//PUT Request
app.put("/update_message/:message_id", verifyToken, async (req, res) => {
  const { message_text } = req.body;
  const { message_id } = req.params;
  const user_id = req.user.user_id;

  // Validate required fields
  if (!message_text) {
    return res.status(400).json({ message: "Please provide message_text" });
  }

  try {
    // Check if the message belongs to the user
    const checkOwnershipQuery =
      "SELECT user_id FROM messages WHERE message_id = $1";
    const checkOwnershipResult = await pool.query(checkOwnershipQuery, [
      message_id,
    ]);

    if (
      checkOwnershipResult.rows.length === 0 ||
      checkOwnershipResult.rows[0].user_id !== user_id
    ) {
      return res
        .status(403)
        .json({ message: "You do not have permission to update this message" });
    }

    // Update the message in the database
    const updateQuery =
      "UPDATE messages SET message_text = $1 WHERE message_id = $2";
    const updateValues = [message_text, message_id];
    await pool.query(updateQuery, updateValues);

    // Send a success response
    res.status(200).json({ message: "Message updated successfully" });
  } catch (error) {
    // Handle errors
    console.error("Error updating message:", error);
    res
      .status(500)
      .json({ message: "An error occurred while updating the message" });
  }
});

//DELETE Request
app.delete("/messages/:message_id", verifyToken, async (req, res) => {
  const { message_id } = req.params;
  const user_id = req.user.user_id;

  try {
    // Check if the message exists and if the user is the author of the message
    const queryCheck =
      "SELECT * FROM messages WHERE message_id = $1 AND user_id = $2";
    const resultCheck = await pool.query(queryCheck, [message_id, user_id]);

    if (resultCheck.rows.length === 0) {
      return res.status(404).json({
        message:
          "Message not found or you are not authorized to delete this message",
      });
    }

    if (resultCheck.rows.length === 0) {
      return res
        .status(403)
        .json({ message: "You are not authorized to delete this message" });
    }
    // Delete the message from the database
    const queryDelete = "DELETE FROM messages WHERE message_id = $1";
    await pool.query(queryDelete, [message_id]);

    // Log the deletion
    console.log(`Message ${message_id} deleted by user ${user_id}`);

    res.status(200).json({ message: "Message deleted successfully" });
  } catch (error) {
    console.error("Error deleting message:", error);
    res
      .status(500)
      .json({ message: "An error occurred while deleting the message" });
  }
});

//GET Request
app.get("/quotes", async (req, res) => {
  pool.query("SELECT * FROM quotes", (err, result) => {
    if (err) {
      console.error("Error executing query:", err);
      res.status(500).send("Error executing query");
    } else {
      res.json(result.rows);
    }
  });
});

//POST Request
app.post("/create_quote", verifyToken, async (req, res) => {
  const { user_id, message_id, quoted_message_id } = req.body;

  // Validate required fields
  if (!user_id || !message_id || !quoted_message_id) {
    return res.status(400).json({
      error: "Please provide user_id, message_id, and quoted_message_id",
    });
  }

  try {
    // Check if the user exists
    const user = await pool.query("SELECT * FROM users WHERE user_id = $1", [
      user_id,
    ]);
    if (user.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    // Check if the message and quoted message exist
    const message = await pool.query(
      "SELECT * FROM messages WHERE message_id = $1",
      [message_id]
    );
    const quotedMessage = await pool.query(
      "SELECT * FROM messages WHERE message_id = $1",
      [quoted_message_id]
    );
    if (message.rows.length === 0 || quotedMessage.rows.length === 0) {
      return res
        .status(404)
        .json({ error: "Message or quoted message not found" });
    }

    // Insert the quote into the database
    const query =
      "INSERT INTO quotes (user_id, message_id, quoted_message_id) VALUES ($1, $2, $3) RETURNING *";
    const values = [user_id, message_id, quoted_message_id];
    const result = await pool.query(query, values);

    // Send a success response with the newly created quote object
    res.status(201).json({ quote: result.rows[0] });
  } catch (error) {
    // Handle errors
    console.error("Error creating quote:", error);
    res
      .status(500)
      .json({ error: "An error occurred while creating the quote" });
  }
});

//GET Request
app.get("/likes", async (req, res) => {
  pool.query("SELECT * FROM likes", (err, result) => {
    if (err) {
      console.error("Error executing query:", err);
      res.status(500).send("Error executing query");
    } else {
      res.json(result.rows);
    }
  });
});

//POST Request
app.post("/create_like/:message_id", verifyToken, async (req, res) => {
  const { message_id } = req.params;
  const user_id = req.user.user_id;

  // Validate required fields
  if (!user_id || !message_id) {
    return res
      .status(400)
      .json({ message: "Please provide user_id and message_id" });
  }

  try {
    // Check if the user has already liked the message
    const existingLike = await pool.query(
      "SELECT * FROM likes WHERE user_id = $1 AND message_id = $2",
      [user_id, message_id]
    );
    if (existingLike.rows.length > 0) {
      // If the user has already liked the message, remove the like
      await pool.query(
        "DELETE FROM likes WHERE user_id = $1 AND message_id = $2",
        [user_id, message_id]
      );
      return res
        .status(200)
        .json({ likeId: null, message: "Like removed successfully" });
    } else {
      // If the user has not already liked the message, add the like
      const result = await pool.query(
        "INSERT INTO likes (user_id, message_id) VALUES ($1, $2) RETURNING like_id",
        [user_id, message_id]
      );
      return res.status(201).json({ likeId: result.rows[0].like_id });
    }
  } catch (error) {
    // Handle errors
    console.error("Error toggling like:", error);
    res
      .status(500)
      .json({ message: "An error occurred while toggling the like" });
  }
});

//POST Request
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // Validate required fields
  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Please provide username and password" });
  }

  try {
    // Retrieve the hashed password from the database for the provided username
    const result = await pool.query(
      "SELECT user_id, password_hash FROM users WHERE username = $1",
      [username]
    );

    // Check if a user with the provided username exists
    if (result.rows.length === 0) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const { user_id, password_hash } = result.rows[0];

    // Compare the provided password with the hashed password stored in the database
    const passwordMatch = await bcrypt.compare(password, password_hash);

    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    // If the credentials are valid, issue a JWT containing the user ID and username
    const token = jwt.sign({ user_id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    // Send the JWT in the response
    res.json({ token });
  } catch (error) {
    // Handle errors
    console.error("Error authenticating user:", error);
    res
      .status(500)
      .json({ message: "An error occurred while authenticating user" });
  }
});

// Server setup
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// Close the pool when app exits
process.on("exit", () => {
  pool.end();
});
