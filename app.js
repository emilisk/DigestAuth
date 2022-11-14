//1.
require("dotenv").config();
const db = require("./utils/database");
//imort model
const User = require("./models/userModel");

var http = require("http");
//2.
var crypt = require("crypto");

////////////////////////////
const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const ejs = require("ejs");
const port = 5050;

////////////////////////////////// PASSPORT JS

const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

/////////////////////////////////

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);

const mongoose = require("mongoose");
// const md5 = require("md5");
const encrypt = require("mongoose-encryption");
const { nextTick } = require("process");

// mongoose.connect("mongodb://localhost:27017/usersDB", {
//   useNewUrlParser: true,
// });

// const userSchema = new mongoose.Schema({
//   email: String,
//   password: String,
// });

// const userSchema = {
//   email: String,
//   password: String,
// };

// userSchema.plugin(encrypt, {
//   secret: process.env.SECRET,
//   encryptedFields: ["password"],
// });

// const User = new mongoose.model("User", userSchema);

//////////////////////
//3.
var credentials = {
  realm: "Digest Authenticatoin",
};
//3a.
var hash;

//4.

function cryptoUsingMD5(data) {
  return crypt.createHash("md5").update(data).digest("hex");
}

//5.
hash = cryptoUsingMD5(credentials.realm);
//6.
function authenticateUser(res) {
  console.log({
    "WWW-Authenticate":
      'Digest realm="' +
      credentials.realm +
      '",qop="auth",nonce="' +
      Math.random() +
      '",opaque="' +
      hash +
      '"',
  });
  res.writeHead(401, {
    "WWW-Authenticate":
      'Digest realm="' +
      credentials.realm +
      '",qop="auth",nonce="' +
      Math.random() +
      '",opaque="' +
      hash +
      '"',
  });
  res.end("Authorization is needed.");
}

//7.
function parseAuthenticationInfo(authData) {
  var authenticationObj = {};
  authData.split(", ").forEach(function (d) {
    d = d.split("=");

    authenticationObj[d[0]] = d[1].replace(/"/g, "");
  });
  console.log(JSON.stringify(authenticationObj));
  return authenticationObj;
}

//8.

app.get("/", function (req, res) {
  res.render("home");
});

app.get("/login", function (req, res) {
  // var server = http.createServer(function (request, response) {
  var authInfo,
    digestAuthObject = {};

  //9.
  if (!req.headers.authorization) {
    authenticateUser(res);
    return;
  }
  //10.
  authInfo = req.headers.authorization.replace(/^Digest /, "");
  authInfo = parseAuthenticationInfo(authInfo);

  User.findOne({ email: authInfo.username }, function (err, foundUser) {
    if (err) {
      console.log(err);
      authenticateUser(res);
      return;
    } else {
      if (foundUser) {
        if (foundUser.email !== authInfo.username) {
          authenticateUser(res);
          return;
        }
      } else {
        authenticateUser(res);
        return;
      }
    }

    //11.
    // if (authInfo.username !== credentials.userName) {
    //   authenticateUser(response);
    //   return;
    // }
    //12.
    digestAuthObject.ha1 = cryptoUsingMD5(
      authInfo.username + ":" + credentials.realm + ":" + foundUser.password
    );
    //13.
    digestAuthObject.ha2 = cryptoUsingMD5(req.method + ":" + authInfo.uri);
    //14.
    var resp = cryptoUsingMD5(
      [
        digestAuthObject.ha1,
        authInfo.nonce,
        authInfo.nc,
        authInfo.cnonce,
        authInfo.qop,
        digestAuthObject.ha2,
      ].join(":")
    );

    digestAuthObject.response = resp;
    console.log(digestAuthObject.response);
    console.log(authInfo.response);

    //15.
    if (authInfo.response !== digestAuthObject.response) {
      authenticateUser(res);
      return;
    }

    // res.end("Congratulations!!!! You are successfully authenticated");
    res.render("secrets");
  });
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/user", function (req, res) {
  User.find({}, function (err, users) {
    if (err) {
      res.send("something went really wrong");
      next();
    }
    res.json(users);
  });
});

app.delete("/user/:id", function (req, res) {
  User.findByIdAndRemove(req.params.id)
    .exec()
    .then((doc) => {
      if (!doc) {
        return res.status(404).end();
      }
    })
    .catch((err) => next(err));
});

app.post("/register", function (req, res) {
  const newUser = new User({
    email: req.body.username,
    password: req.body.password,
  });

  newUser.save(function (err) {
    if (err) {
      console.log(err);
    } else {
      res.render("secrets");
    }
  });
});

// app.get("/logout", function (req, res) {
//   // req.logout();
//   res.redirect("/");
// });

//16.
app.listen(5050, function () {
  db();

  console.log(`Server started on port ${port}`);

  // (function () {
  //   try {
  //     //create a new user
  //     User.create(
  //       {
  //         email: "simon@gmail.com",
  //         password: "12345",
  //       },
  //       (err, user) => {
  //         if (err) throw new Error(err);
  //         console.log(`The user ${user.email} has been created`);
  //       }
  //     );
  //   } catch (err) {
  //     console.log(err);
  //   }
  // })();
});

//////////////////////////////////////////////////////////////////////////////////////////////////

const crypto = require("crypto");

app.use(express.urlencoded({ extended: true }));
//register session in express
app.use(
  session({
    secret: "PasswordResetNodeJs",
    resave: true,
    saveUninitialized: true,
  })
);

//generate reset link
app.post("/reset", async (req, res) => {
  try {
    //find a document with such email address
    const user = await User.findOne({ email: req.body.email });
    //check if user object is not empty
    if (user) {
      //generate hash using the user object
      const hash = new User(user).passwordResetHash();
      //generate a password reset link
      const resetLink = `http://localhost:5050/reset?email=${user.email}&hash=${hash}`;
      //remember to send a mail to the user
      return res.status(200).json({
        resetLink,
      });
    } else {
      //respond with an invalid email
      return res.status(400).json({
        message: "Email Address does not exist",
      });
    }
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
});

//reset route
app.get("/reset", async (req, res) => {
  try {
    //check for email and hash in query parameter
    if (req.query && req.query.email && req.query.hash) {
      //find user with suh email address
      const user = await User.findOne({ email: req.query.email });
      //check if user object is not empty
      if (user) {
        //now check if hash is valid
        if (new User(user).verifyPasswordResetHash(req.query.hash)) {
          //save email to session
          req.session.email = req.query.email;
          //issue a password reset form
          return res.render(__dirname + "/views/new_pass.ejs");
        } else {
          return res.status(400).json({
            message: "You have provided an invalid reset link",
          });
        }
      } else {
        return res.status(400).json({
          message: "You have provided an invalid reset link",
        });
      }
    } else {
      //if there are no query parameters, serve the normal request form
      return res.render(__dirname + "/views/reset.ejs");
    }
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
});

//update password
app.post("/reset-pass", async (req, res) => {
  try {
    if (!req.session || !req.session.email) return res.redirect("/login");
    //check if both passwords are equal
    if (req.body.pass !== req.body.conpass)
      return res.status(400).json({
        message: "Both passwords do not match",
      });
    //update document
    const updatedDoc = await User.findOneAndUpdate(
      { email: req.session.email },
      { $set: { password: req.body.pass, __enc_message: false } }
    );
    //password update successful
    if (updatedDoc) {
      //remove email from session
      req.session.email = "";
      //return success messa
      return res.status(200).json({
        message: "Your password has been updated",
      });
    }
    return res.status(200).json({
      message: "Your password was not updated",
    });
    //remember to send a mail to the user
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
});

app.get("/remove", async (req, res) => {
  try {
    //check for email and hash in query parameter
    if (req.query && req.query.email && req.query.hash) {
      //find user with suh email address
      const user = await User.findOne({
        email: req.query.email,
      });
      //check if user object is not empty
      if (user) {
        //now check if hash is valid
        if (new User(user).verifyPasswordResetHash(req.query.hash)) {
          //save email to session
          req.session.email = req.query.email;
          //issue a password reset form
          User.findOneAndDelete(req.query.email)
            .exec()
            .then((doc) => {
              return res.json({ User: "Deleted" });
              if (!doc) {
                return res.status(404).end();
              }
            });

          // return res.json({ name: "Emilis" });
          // return res.render(__dirname + "/views/new_pass.ejs");
        } else {
          return res.status(400).json({
            message: "You have provided an invalid reset link",
          });
        }
      } else {
        return res.status(400).json({
          message: "You have provided an invalid reset link",
        });
      }
    } else {
      //if there are no query parameters, serve the normal request form
      return res.render(__dirname + "/views/remove.ejs");
    }
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
});

app.post("/remove", async (req, res) => {
  try {
    var password = req.body.password;
    const messageToSearchWith = new User({ password });
    messageToSearchWith.encryptFieldsSync();
    //find a document with such email address
    const user = await User.findOne({
      email: req.body.email,
      password: messageToSearchWith.password,
    });
    //check if user object is not empty
    if (user) {
      //generate hash using the user object
      const hash = new User(user).passwordResetHash();
      //generate a password reset link
      const resetLink = `http://localhost:5050/remove?email=${user.email}&hash=${hash}`;
      //remember to send a mail to the user
      return res.status(200).json({
        resetLink,
      });
    } else {
      //respond with an invalid email
      return res.status(400).json({
        message: "Email Address or password are wrong",
      });
    }
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
});

app.delete("/remove/:email", function (req, res) {
  User.findByIdAndRemove(req.params.email)
    .exec()
    .then((doc) => {
      if (!doc) {
        return res.status(404).end();
      }
    })
    .catch((err) => next(err));
});
