const jwt = require('jsonwebtoken');

const authenticateRefreshToken = (req, res, next) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.sendStatus(401);  // If there is no token

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);  // If token is no longer valid
    req.user = user;
    next();
  });
};

module.exports = authenticateRefreshToken;