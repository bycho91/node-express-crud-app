const { json, application } = require("express");
const express = require("express");
const CryptoJS = require("crypto-js");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

dotenv.config();

const app = express();
app.use(express.json());

// empty array to persist the users data
const users = [];

// REGISTER
app.post("/api/register", (req, res) => {
  //validate username, password, email is given
  if (
    req.body.username == "" ||
    req.body.password == "" ||
    req.body.email == ""
  )
    res.status(400).json("Please fill out all information");
  else {
    // body -> username, password

    // create new user
    const newUser = {
      id: uuidv4(),
      username: req.body.username,
      password: CryptoJS.AES.encrypt(
        req.body.password,
        process.env.SEC
      ).toString(),
      email: req.body.email,
      isAdmin: req.body.isAdmin || false,
    };

    //take the new user and push to users array
    users.push(newUser);
    res.status(200).json(`${newUser.username} has been created`);
  }
});

// GET all users
app.get("/api/users", async (req, res) => {
  const allUsers = await users.map((user) => ({
    id: user.id,
    username: user.username,
    email: user.email,
    isAdmin: user.isAdmin,
  }));

  if (!allUsers) res.status(400).json("No users found in database");
  else res.status(200).json(allUsers);
});

// LOGIN USER
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

    if (!user) res.status(400).json("Credentials invalid");
    else {
      //create an access token using jwt
      const accessToken = jwt.sign(
        {
          id: user.id,
          username: user.username,
          isAdmin: user.isAdmin,
        },
        process.env.SEC,
        { expiresIn: "2d" }
      );

      res.status(200).json({
        username: user.username,
        id: user.id,
        isAdmin: user.isAdmin,
        accessToken,
      });
    }
  } catch (error) {
    res.status(400).json(error);
  }
});

// Verify User
const verifyUser = async (req, res, next) => {
  const authHeader = req.headers.token;
  if (!authHeader) {
    return res.status(400).json("Token not passed");
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

// DELETE USER
app.delete("/api/users/:userId", verifyUser, (req, res) => {
  if (req.user.id === req.params.userId || req.user.isAdmin) {
    users.forEach((user) => {
      if (user.id === req.params.userId) {
        users.splice(users.indexOf(user.id));
      }
    });
    res.status(200).json(`User ${req.params.userId} has been deleted`);
  } else {
    res.status(403).json("You are not permitted to delete this user");
  }
});

//////////////////////////////////////////////////////////////////////////

app.listen(5000, () => {
  console.log("SERVER STARTED");
});
