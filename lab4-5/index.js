const express = require("express");
const path = require("path");
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");
const axios = require("axios");

require("dotenv").config();

const port = 3000;

const leftTimeToRefresh = 80000

const app = express();
app.use(express.json());

const domain = process.env.domain
const audience = process.env.audience
const clientId = process.env.client_id
const clientSecret = process.env.client_secret

const jwksClientInstance = jwksClient({
  jwksUri: `https://${domain}/.well-known/jwks.json`,
  cache: true,
});

const indexPath = path.join(__dirname + "/index.html");


app.get("/", (req, res) => {
  const accessToken = req?.headers["authorization"];
  const refreshToken = req?.headers["refreshtoken"];
  if (accessToken) {
      const decodedToken = jwt.decode(accessToken, {complete: true});
      if (!decodedToken) {
        res.sendFile(path.join(indexPath));
        return;
      }
      const decodedHeader = decodedToken?.header;

      const currentTime = Math.floor(Date.now() / 1000);
      const timeExpiresToken = decodedToken.payload.exp;

      jwksClientInstance.getSigningKey(decodedHeader.kid, (error, key) => {
        if(error) {
          console.log(error);
        }
        const signingKey = key.publicKey || key.rsaPublicKey;
        jwt.verify(accessToken, signingKey, (error, decoded) => {
          if (error) {
            return res.status(401).sendFile(indexPath);
          }
          if(refreshToken && timeExpiresToken - currentTime <= leftTimeToRefresh){
            const refreshRequestBody = {
              grant_type: 'refresh_token',
              client_id: clientId,
              client_secret: clientSecret,
              refresh_token: refreshToken,
              audience: audience,
            };
            
            axios
              .post(`https://${domain}/oauth/token`, refreshRequestBody)
              .then((response) => {
                const newAccessToken = response.data.access_token;
                return res.status(200).json({ newAccessToken: newAccessToken, id: decoded.sub });
              })
              .catch((error) => {
                console.log(error);
                return res.status(401).sendFile(indexPath);
              });
              
          } else {
            return res.status(200).json({id: decoded.sub });
          }
        });
      });
  } else {
    res.sendFile(path.join(indexPath));
  }
});


app.get("/logout", (req, res) => {
  res.redirect("/");
});


app.post('/api/login', (req, res) => {
  const { login, password } = req.body;

  const requestBody = {
    audience: audience,
    grant_type: "http://auth0.com/oauth/grant-type/password-realm",
    client_id: clientId,
    client_secret: clientSecret,
    username: login,
    password: password,
    realm: "Username-Password-Authentication",
    scope: "offline_access"
  };
  
  axios
    .post(`https://${domain}/oauth/token`, requestBody)
    .then((response) => {
      const accessToken = response.data.access_token;
      const refreshToken = response.data.refresh_token;
      res.json({ accessToken, refreshToken });
    })
    .catch((error) => {
      console.log(error);
      res.status(401).json("Login failed" + error?.message);
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
      console.log(requestBody.email, requestBody.password);
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