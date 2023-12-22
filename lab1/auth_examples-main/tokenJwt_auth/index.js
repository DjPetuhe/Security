const express = require('express');

const path = require('path');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const port = 3000;

const JWT_SECRET = 'JWT_SECRET';
const JWT_EXPIRES = '60s';

const SESSION_KEY = 'Authorization';

app.use((req, res, next) => {
  let curUser = {};
  let token = req.get(SESSION_KEY);

  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      curUser = { username: decoded.username, login: decoded.login };
    } catch (err) { }
  }
  
  req.user = curUser;
  next();
});

app.get('/', (req, res) => {
  if (req.user.username) {
    return res.json({
      username: req.user.username,
      logout: 'http://localhost:3000/logout',
    });
  }
  res.sendFile(path.join(__dirname + '/index.html'));
});

app.get('/logout', (req, res) => {
  sessions.destroy(req, res);
  res.redirect('/');
});

const users = [
  {
    login: 'Login',
    password: 'Password',
    username: 'Username',
  },
  {
    login: 'Login1',
    password: 'Password1',
    username: 'Username1',
  },
];

app.post('/api/login', (req, res) => {
  const { login, password } = req.body;

  const user = users.find(user => user.login == login && user.password == password);

  if (user) {
    const token = jwt.sign(
      {
        username: user.username,
        login: user.login,
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    console.log(token);
    
    res.json({ token });
  }

  res.status(401).send();
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});