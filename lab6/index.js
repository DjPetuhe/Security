const express = require("express");
const path = require("path");
const axios = require("axios");
const { auth, requiresAuth } = require('express-openid-connect');
require("dotenv").config();

const domain = process.env.domain
const audience = process.env.audience
const clientId = process.env.client_id
const clientSecret = process.env.client_secret
const baseUrl = "http://localhost:3000";

const config = {
    authRequired: true,
    auth0Logout: true,
    baseURL: baseUrl,
    clientID: clientId,
    issuerBaseURL: `https://${domain}`,
    secret: clientSecret,
    logoutParams: {
      returnTo: `${baseUrl}/logout`,
    }
  };

const app = express();
app.set('view engine', 'ejs');
app.use(express.json());
app.use(auth(config));

const port = 3000;

const indexPath = path.join(__dirname + "/index.html");

app.get("/", (req, res) => {
  if (req.oidc.isAuthenticated()) {
    res.render('profile', { User: req.oidc.user.email, Id: req.oidc.user.sub });
  } else {
    res.sendFile(path.join(indexPath));
  }
});

app.post('/api/login', (req, res) => {
  const { login, password } = req.body;

  const requestBody = {
    audience: audience,
    grant_type: "authorization code",
    client_id: clientId,
    client_secret: clientSecret,
    username: login,
    password: password,
  };
  
  axios
    .post(`https://${domain}/oauth/token`, requestBody)
    .then((response) => {
      const token = response.data.access_token;
      res.json({ token });
    })
    .catch((error) => {
      console.log(error);
      res.status(401).json("Login failed: " + error?.message);
    });
    
});

app.post('/api/register', (req, res) => {
  axios
  .post(`https://${domain}/oauth/token`, {
    client_id: clientId,
    client_secret: clientSecret,
    audience: audience,
    grant_type: "client_credentials",
  })
  .then((response) => {
    const accessToken = response.data.access_token;

    const requestBody = {
      email: req.body.login,
      password: req.body.password,
      connection: "Username-Password-Authentication",
    };

    axios
    .post(`${audience}users`, requestBody, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    })
    .then((response) => {
      res.json(requestBody.email + " registration succeed");
    })
    .catch((error) => {
      console.log(error);
      res.status(401).json("Registration failed: " + error?.message);
    });
  });
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});