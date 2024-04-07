/** Middleware for handling req authorization for routes. */

const jwt = require('jsonwebtoken');
const { SECRET_KEY } = require('../config');
const ExpressError = require('../helpers/expressError');

/** Authorization Middleware: Requires user is logged in. */

function requireLogin(req, res, next) {
  try {
    // console.log("*****************res**********************",res);
    // console.log("*****************req**********************",req);

    if (req.curr_username) {
      return next();
    } else {
      return next({ status: 401, message: 'Unauthorized' });
    }
  } catch (err) {
    return next(err);
  }
}

/** Authorization Middleware: Requires user is logged in and is staff. */

function requireAdmin(req, res, next) {
  try {
    if (req.curr_admin) {
      return next();
    } else {
      return next({ status: 401, message: 'Unauthorized' });
    }
  } catch (err) {
    return next(err);
  }
}

/** Authentication Middleware: put user on request
 *
 * If there is a token, verify it, get payload (username/admin),
 * and store the username/admin on the request, so other middleware/routes
 * can use it.
 *
 * It's fine if there's no token---if not, don't set anything on the
 * request.
 *
 * If the token is invalid, an error will be raised.
 *
 **/

function authUser(req, res, next) {
  try {
    //bug #1 here, 
    // I would not put my token in body or query
    // like previously chapter, i would put token in header
    // also jwt.decode does not validate.
    // const token = req.body._token || req.query._token;
    // if (token) {
    //   let payload = jwt.decode(token);
    //   console.log(payload);
    //   req.curr_username = payload.username;
    //   req.curr_admin = payload.admin;
    // }
    const authHeader = req.headers && req.headers.authorization;
    if (!authHeader){
      throw new ExpressError("Missing or invalid authorization header", 400);
    }
    const token = authHeader.replace(/^[Bb]earer /, "").trim();
    if (token) {
      let payload = jwt.verify(token, SECRET_KEY);
      req.curr_username = payload.username;
      req.curr_admin = payload.admin;
    }
    
    return next();
  } catch (err) {
    err.status = 401;
    return next(err);
  }
} // end

module.exports = {
  requireLogin,
  requireAdmin,
  authUser
};
