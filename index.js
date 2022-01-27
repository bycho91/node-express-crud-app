const express = require("express");
const dotenv = require("dotenv");
const CryptoJS = require("crypto-js");
const { v4: uuidv4 } = require("uuid");
const jwt = require("jsonwebtoken");
dotenv.config();

const app = express();
app.use(express.json());
const users = [];

// CREATE - REGISTER
app.post("/api/register", (req, res) => {
  if (req.body.username && req.body.email && req.body.password) {
    const newUser = {
      id: uuidv4(),
      username: req.body.username,
      email: req.body.email,
      password: CryptoJS.AES.encrypt(
        req.body.password,
        process.env.SEC
      ).toString(),
      isAdmin: req.body.isAdmin || false,
    };

    users.push(newUser);
    res.status(200).json(`${newUser.username} has been added!`);
  } else {
    res
      .status(400)
      .json("Please fill out all information[username, password, email]");
  }
});

// READ - Get All Users
app.get("/api/users", async (req, res) => {
  const allUsers = await users.map((user) => ({
    id: user.id,
    username: user.username,
    email: user.email,
    isAdmin: user.isAdmin,
  }));

  if (allUsers.length < 1) res.json("No users in the database");
  else res.status(200).json(allUsers);
});

// READ - Get a particular user
app.get("/api/users/:username", async (req, res) => {
  const user = users.find((user) => user.username === req.params.username);
  if (!user) res.status(400).json("User not found in database");
  else
    res.status(200).json({
      username: user.username,
      email: user.email,
      isAdmin: user.isAdmin,
    });
});

// LOGIN - give access token with JWT
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await users.find(
      (user) =>
        user.username === username &&
        CryptoJS.AES.decrypt(user.password, process.env.SEC).toString(
          CryptoJS.enc.Utf8
        ) === password
    );

    if (!user) res.status(400).json("Invalid Credentials");
    else {
      const accessToken = jwt.sign(
        {
          id: user.id,
          isAdmin: user.isAdmin,
        },
        process.env.SEC,
        { expiresIn: "3d" }
      );

      res.status(200).json({
        id: user.id,
        username: user.username,
        email: user.email,
        isAdmin: user.isAdmin,
        accessToken,
      });
    }
  } catch (error) {
    res.status(400).json(error);
  }
});

// DELETE
const verifyUser = (req, res, next) => {
  const authHeader = req.headers.token;
  if (!authHeader) {
    res.status(400).json("Token not passed");
  } else {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, process.env.SEC, (err, payload) => {
      if (err) res.status(400).json(err);
      else {
        req.user = payload;
        next();
      }
    });
  }
};

app.delete("/api/users/:userId", verifyUser, async (req, res) => {
  if (req.user.id === req.params.userId || req.user.isAdmin) {
    users.forEach((user) => {
      if (user.id === req.params.userId)
        users.splice(users.indexOf(req.params.userId));
    });
    res.status(200).json(`USER has been deleted`);
  } else {
    res.status(403).json("You are not permitted to delete this user");
  }
});

////////////////////////////////////////////////
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`SERVER STARTED ON PORT ${PORT}`));
