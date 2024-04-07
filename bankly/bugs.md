- BUG #1: POST auth/login doesn't have await keyword in front of User.authenticate.
This works because admin is set as false as default value 


- BUG #2: 
DELETE user/:username, there's no await in front of User.Delete calls.
It passes because it doesn't check whether user is deleted.

- BUG #3:
There wasn't throw on

  static async get(username) {
    const result = await db.query(
      `SELECT username,
                first_name,
                last_name,
                email,
                phone
         FROM users
         WHERE username = $1`,
      [username]
    );

    const user = result.rows[0];

    if (!user) {

      // Fixed BUG3 
      throw new ExpressError(`No such user`, 404);

      // # BUG 3? throw is missing
      // new ExpressError('No such user', 404);
    }

    return user;
  }

- BUG # 4
function authUser(req, res, next) {
  try {
    //bug #4 here, 
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

- BUG #5
Security issue, on patch route, admin can change username and password, this should throw error

- Missing Tests

// Missing Test, missing register information
  test("missing email information to register", async function(){
    const response = await request(app)
    .post("/auth/register")
    .send({
      username: "new_user",
        password: "new_password",
        first_name: "new_first",
        last_name: "new_last",
        phone: "1233211221"
    });

    expect(response.statusCode).toBe(500);
    expect(response.body).toEqual({
      message: 'null value in column "email" of relation "users" violates not-null constraint'
    });
  })

// missing a test
  test("Wrong password", async function(){
    const response = await request(app)
    .post("/auth/login")
    .send({
      username: "u3",
      password: "pwd4"
    });
    expect(response.statusCode).toBe(401);
    expect(response.body).toEqual({"message": 'Cannot authenticate', "status": 401})
  })