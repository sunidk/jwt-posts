const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const uuid = require("uuid");
const logger = require("./logger");

const app = express();
app.use(express.json());
app.use(bodyParser.json());

const PORT = 3000;
const SECRET = "secretkey";

// In-memory storage
const users = [];
const posts = [];

// Function to authenticate JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) {
    logger.warn("Authentication failed: Token required");
    return res.status(401).json({ message: "Token required" });
  }
  jwt.verify(token, SECRET, (err, user) => {
    if (err) {
      logger.warn("Authentication failed: Invalid token");
      return res.status(403).json({ message: "Invalid token" });
    }
    req.user = user;
    next();
  });
}

// User creation
app.post("/register", (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      logger.warn("Register failed: username/password missing");
      return res
        .status(400)
        .json({ message: "username and password required" });
    }

    if (users.find((user) => user.username === username)) {
      logger.warn(`Register failed: ${username} already exists`);
      return res.status(409).json({ message: "User already exists" });
    }

    users.push({ username, password });
    logger.info(`User registered: ${username}`);
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    logger.error(`Register error: ${error.message}`);
    res.status(500).json({ message: "Internal server error" });
  }
});

// User login
app.post("/login", (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      logger.warn("Login failed: username/password missing");
      return res
        .status(400)
        .json({ message: "username and password required" });
    }

    const user = users.find(
      (user) => user.username === username && user.password === password
    );
    if (!user) {
      logger.warn(`Login failed: Invalid credentials for ${username}`);
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ username }, SECRET, { expiresIn: "1h" });
    logger.info(`User logged in: ${username}`);
    res.status(200).json({ token });
  } catch (error) {
    logger.error(`Login error: ${error.message}`);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Post creation
app.post("/posts", authenticateToken, (req, res) => {
  try {
    const { content } = req.body;
    if (!content) {
      logger.warn("Post creation failed: Content missing");
      return res.status(400).json({ message: "Content is required" });
    }

    const post = {
      id: uuid.v4(),
      author: req.user.username,
      content,
      likes: [],
      createdAt: new Date(),
    };
    posts.push(post);
    logger.info(`Post created by ${req.user.username}: ${post.id}`);
    res.status(201).json(post);
  } catch (error) {
    logger.error(`Post creation error: ${error.message}`);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Post liking
app.post("/posts/:id", authenticateToken, (req, res) => {
  try {
    const postId = req.params.id;
    const post = posts.find((post) => post.id === postId);

    if (!post) {
      logger.warn(`Like failed: Post not found - ${postId}`);
      return res.status(404).json({ message: "Post not found" });
    }

    if (!post.likes.includes(req.user.username)) {
      post.likes.push(req.user.username);
      logger.info(`Post liked by ${req.user.username}: ${postId}`);
    }

    res.status(200).json({ message: "Post liked", likes: post.likes.length });
  } catch (error) {
    logger.error(`Post like error: ${error.message}`);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Post deletion
app.delete("/posts/:id", authenticateToken, (req, res) => {
  try {
    const postId = req.params.id;
    const postIndex = posts.findIndex((post) => post.id === postId);

    if (postIndex === -1) {
      logger.warn(`Delete failed: Post not found - ${postId}`);
      return res.status(404).json({ message: "Post not found" });
    }

    if (posts[postIndex].author !== req.user.username) {
      logger.warn(`Unauthorized delete attempt by ${req.user.username}`);
      return res
        .status(403)
        .json({ message: "Unauthorized to delete this post" });
    }

    posts.splice(postIndex, 1);
    logger.info(`Post deleted by ${req.user.username}: ${postId}`);
    res.status(200).json({ message: "Post deleted successfully" });
  } catch (error) {
    logger.error(`Post delete error: ${error.message}`);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Post listing
app.get("/posts", (req, res) => {
  try {
    logger.info("Posts fetched");
    res.status(200).json(posts);
  } catch (error) {
    logger.error(`Post listing error: ${error.message}`);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Server start
app.listen(PORT, () => {
  logger.info(`Server started and listening on port ${PORT}`);
});
