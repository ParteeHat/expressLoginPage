require('dotenv').config()
const sqlite3 = require('sqlite3').verbose()
const jwt = require('jsonwebtoken')
const {randomBytes, scryptSync} = require('crypto')
const express = require("express");
const app = express();
const port = 3000;

const db = new sqlite3.Database(`${__dirname}/users.db`, sqlite3.OPEN_READWRITE, (err) => {
  if (err) return console.error(err.message);
})


app.use(express.json())

app.get("/", function (req, res) {
  res.sendFile(`${__dirname}/index.html`);
});

app.get("/register", function (req, res) {
  res.sendFile(`${__dirname}/register.html`);
});

app.get("/login", function (req, res) {
  res.sendFile(`${__dirname}/login.html`);
});

app.post("/register", function (req, res) {
  const body = req.body;

  if (!body.username || !body.password) {
    res.status(418).send({message: "Input is empty"})
    return;
  } else if (body.password.length >= 257) {
    res.status(418).send({message: "Password is over 256 characters"})
    return;
  } else if (body.username.length >= 33) {
    res.status(418).send({message: "Username is over 32 characters"})
    return;
  } else {
    db.all("SELECT * FROM users", [], (err, rows) => {
      if (err) return console.error(err.message);
      
      let userExists = false
      rows.forEach(row => {
        if(row.username == body.username) {
          userExists = true
        }
      })
  
      if(!userExists) {
        const salt = randomBytes(16).toString('hex')
        db.run(`INSERT INTO users (username, salt, hashedPassword) VALUES (?, ?, ?)`, [body.username, salt, scryptSync(body.password, salt, 64).toString('hex')], (err) => {if(err) return console.error(err.message)})
        const user = {name: body.username}
        const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET)
        res.json({accessToken: accessToken})
        console.log("REGISTERED ACCOUNT")
      } else {
        console.log("USER ALREADY EXISTS")
        res.status(418).send({message: "User Already Exists"})
        return;
      }
    })
  }
});

app.post('/login', (req, res) => {
  const body = req.body;

  if (!req.body.username || !req.body.password) {
    res.status(418).send({message: "Input is empty"})
    return;
  }

  db.all("SELECT * FROM users", [], (err, rows) => {
  
    if (err) return console.error(err.message);
    
    let foundUser = false
    rows.forEach(row => {
      if(row.username == body.username) {
        if(row.hashedPassword == scryptSync(body.password, row.salt, 64).toString('hex')) {
          const user = {name: body.username}
          const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET)
          res.json({accessToken: accessToken})
          console.log("CORRECT PASSWORD")
        } else {
          res.status(418).send({message: "Password is Incorrect"})
          console.log("WRONG PASSWORD")
        }
        foundUser = true;
        return;
      }
    })
    if(!foundUser) {
      res.status(418).send({message: "User Doesn't Exist"})
      console.log("COULDN'T FIND USER")
      return;
    }
  })
})

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]
  if (token == null) return res.sendStatus(403)
  
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403)
    req.user = user
    next()
  })
}

//SAMPLE CALL WITH VERIFICATION
const posts = [
  {
    username: 'aaa',
    context: 'Lorem'
  },
  {
    username: 'Jane',
    context: 'Ipsum'
  }
]
app.get('/getPosts', authenticateToken, (req, res) => {
  res.json(posts.filter(post => post.username === req.user.name))
})

app.listen(port, function () {
  console.log(`Example app listening on port ${port}!`);
});

//db.run("CREATE TABLE users (username TEXT, salt TEXT, hashedPassword TEXT)")
//db.run("DROP TABLE users")