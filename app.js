var express = require("express");
var cors = require("cors");
var bodyParser = require("body-parser");
const mysql = require("mysql2/promise");
const PORT = process.env.PORT || 4000;

var connection = {};
var app = express();
var jwt = require("jsonwebtoken");
var jsonParser = bodyParser.json();
const secret = "ระบบกิจการนักศึกษา";
const bcrypt = require("bcrypt");
const saltRounds = 10;
app.use(cors());
app.use(express.json());
app.use(jsonParser);

const create_connection = async () => {
  try {
    const connection = await mysql.createConnection({
      host: "localhost",
      user: "root",
      database: "stou",
    });
    
    // Attempt to execute a simple query to check the connection
    await connection.execute('SELECT 1');
    
    console.log('Connected to MySQL database successfully!');
    
    return connection; // Return the connection object
  } catch (error) {
    console.error('Error connecting to MySQL database:', error);
    throw error; // Rethrow the error
  }
};

// Check connection
create_connection()
  .then((connection) => {
    // Connection is already checked inside create_connection function
    // You can perform any additional operations here if needed
  })
  .catch((err) => {
    console.error('Error creating MySQL connection:', err);
  });



const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(" ")[1];

    jwt.verify(token, secret, (err, users) => {
      if (err) {
        res.status(403);
        res.send({
          status: "forbidden",
          message: "Access Token Invalid",
        });
        return;
      }

      req.users = users;
      next();
    });
  } else {
    res.status(401);
    res.send({
      status: "forbidden",
      message: "No Authorization Header",
    });
  }
};

app.post("/auth", function (req, res, next) {
  try {
    const token = req.headers.authorization.split(" ")[1];
    var decoded = jwt.verify(token, secret);
    res.json({ status: "Verified", decoded });
  } catch (err) {
    res.json({ status: "error", message: err.message });
  }
});

app.post("/auth/user", authenticateJWT, (req, res) => {
  const email = req.user.email;
  connection.query(
    "SELECT * FROM `user` WHERE `email` = ?",
    [email],
    function (err, results) {
      res.json(results);
    }
  );
});

app.post("/register", jsonParser, async (req, res, next) => {
  let connection = await create_connection();

  var email = req.body.email;
  var values = "";
  values = values + "'" + email + "'";

  let query = "SELECT email FROM user WHERE email = " + values;
  let [rows] = await connection.query(query, [], (error, results) => {
    if (error) throw error;
    console.log(error || results);
  });
  console.log(query);
  if (rows.length > 0) {
    return res.json({
      status: "registered",
      message: "Email นี้มีข้อมูลอยู่ในระบบอยู่แล้ว",
      rows,
    });
  }

  let hash_password = await bcrypt.hash(req.body.password, saltRounds);
  // insert new users to database

  let [register] = await connection.query(
    "INSERT INTO `user`(`user_id`, `user_name`, `user_age`, `user_career`,`department`,`program`, `user_address`, `email`, `password`, `user_tel`) VALUES (?,?,?,?,?,?,?,?,?,?)",
    [
      req.body.user_id,
      req.body.user_name,
      req.body.user_age,
      req.body.user_career,
      req.body.department,
      req.body.program,
      req.body.user_address,
      req.body.email,
      hash_password,
      req.body.user_tel
    ]
  );

  return res.json({
    status: "ok",
    message:
      "บัญชีผู้ใช้รหัสประจำตัว : " +
      req.body.user_id +
      " ลงทะเบียนเรียบร้อย",
    register,
  });
});

app.post("/login", jsonParser, async function (req, res, next) {
  let connection = await create_connection();
  let [user] = await connection.query("SELECT * FROM `user` WHERE `email` = ?", [
    req.body.email,
]);

  if (user.length == 0) {0
    res.json({ status: "error", message: "ไม่พบ Email ในระบบ" });
    return;
  }

  const match = await bcrypt.compare(req.body.password, user[0].password);
  if (match) {
    var token = jwt.sign({ email: user[0].email }, secret, {
      expiresIn: "1h",
    });
    res.json({
      status: "success",
      message: "ยินดีต้อนรับ",
      token,
      user: user[0],
    });
  } else {
    res.json({
      status: "Invalid password",
      message: "รหัสผ่านไม่ถูกต้อง",
    });
  }
});

app.post("/reset-password", jsonParser, async (req, res) => {
  let connection = await create_connection();
  const { email, newPassword } = req.body;

  try {
    console.log('Attempting to execute query...');
    // Check if the email exists in the database
    const [rows] = await connection.execute("SELECT * FROM user WHERE email = ?", [email]);
    
    // If the email does not exist, return an error
    if (rows.length === 0) {
      return res.status(404).json({ 
        status:"error",
        message: "ไม่พบ email ของผู้ใช้ในระบบ" 
      });
    }

    // Hash the new password before updating the database
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update the user's password in the database
    await connection.execute("UPDATE user SET password = ? WHERE email = ?", [hashedPassword, email]);

    // Send a success response
    res.status(200).json({
      status:"ok",
      });
  } catch (error) {
    console.error("Error resetting password:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});


// CRUD user in database

app.get("/roles", async function (req, res, next) {
  let connection = await create_connection();
  let [rows] = await connection.query("SELECT * FROM `roles`");
  return res.json(rows);
});

app.get("/users/:user_id", async function (req, res, next) {
  let connection = await create_connection();
  const user_id = req.params.user_id;
  let [rows] = await connection.query(
    "SELECT * FROM `users` LEFT JOIN roles ON users.role_id = roles.role_id WHERE `user_id` = ?",
    [user_id]
  );
  return res.json(rows[0]);
});

app.delete("/delete", async function (req, res, next) {
  let connection = await create_connection();
  let [rows, err] = await connection.query(
    "DELETE FROM `users` WHERE user_id = ?",
    [req.body.user_id]
  );
  if (err) {
    res.json({ error: err });
  }
  const id = req.body.user_id;
  return res.json({
    status: "ok",
    message: "User with USER_ID : " + id + " is deleted successfully.",
    rows,
  });
});

app.get("/swn", async function (req, res, next) {
  let connection = await create_connection();
  let [rows] = await connection.query("SELECT * FROM `swn`");
  return res.json(rows);
});

app.get("/teacherlist",async function (req,res,next){
  let connection = await create_connection();
  let [rows] = await connection.query("SELECT user.user_id, user.user_name, user.department, user.user_tel, user.lineID ,club.club_name FROM user JOIN club_advisor ON club_advisor.user_id = user.user_id JOIN club ON club_advisor.club_id = club.club_id;");
  return res.json(rows);
});

app.get("/swn/:swn_id", async function (req, res, next) {
  try {
    let connection = await create_connection();
    const swn_id = req.params.swn_id;
    let [rows] = await connection.query( 
      "SELECT * FROM `club` JOIN swn ON club.swn_id = swn.swn_id WHERE club.swn_id = ?",
      [swn_id]
    );
    return res.json(rows);
  } catch (error) {
    console.error('Error fetching data:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get("/club/:club_id", async function (req, res, next) {
  try {
    let connection = await create_connection();
    const club_id = req.params.club_id;
    let [rows] = await connection.query(
      "SELECT * FROM `activity` JOIN club ON activity.club_id = club.club_id WHERE activity.club_id = ?",
      [club_id]
    );
    return res.json(rows);  
  } catch (error) {
    console.error('Error fetching data:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get("/clubname/:club_id", async function (req, res, next) {
  let connection = await create_connection();
  const club_id = req.params.club_id;
  let [rows] = await connection.query(
    "SELECT * FROM `club` WHERE `club_id` = ?",
    [club_id]
  );
  return res.json(rows[0]);
});

app.get("/activity/:activity_id", async function (req, res, next) {
  try {
    let connection = await create_connection();
    const activity_id = req.params.activity_id;
    let [rows] = await connection.query(
      "SELECT user.user_id,user.user_name,activity.club_id FROM `user` JOIN activity_paticipant ON activity_paticipant.user_id=user.user_id JOIN activity ON activity_paticipant.activity_id = activity.activity_id WHERE activity_paticipant.activity_id = ?",
      [activity_id]
    );
    return res.json(rows);
  } catch (error) {
    console.error('Error fetching data:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get("/club/:club_id/teacher", async function (req, res, next) {
  try {
    let connection = await create_connection();
    const club_id = req.params.club_id;
    let [rows] = await connection.query(
      "SELECT user.user_id, user.user_name FROM `user` JOIN club_advisor ON club_advisor.user_id = user.user_id WHERE club_advisor.club_id = ? ;",
      [club_id]
    );
    return res.json(rows);
  } catch (error) {
    console.error('Error fetching data:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get("/club/:club_id/committee", async function (req, res, next) {
  try {
    let connection = await create_connection();
    const club_id = req.params.club_id;
    let [rows] = await connection.query(
      "SELECT committee_role.committee_role_name, user.user_id, user.user_name FROM committee_role INNER JOIN club_committee ON committee_role.committee_role_id = club_committee.committee_role_id INNER JOIN user ON club_committee.user_id = user.user_id WHERE club_committee.club_id = ?;",
      [club_id]
    );
    return res.json(rows);
  } catch (error) {
    console.error('Error fetching data:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/club/:club_id/register', jsonParser, async (req, res) => {
  try {
    const clubId = req.params.club_id;
    const userData = req.headers['user'];

    if (!clubId || !userData) {
      throw new Error('Club ID and User data are required');
    }

    const userDataObj = JSON.parse(userData);
    const connection = await create_connection();
    const [existingRegistrations] = await connection.query("SELECT * FROM club_member WHERE club_id = ? AND user_id = ?", [clubId, userDataObj.user_id]);
    const [memberofother] = await connection.query("SELECT * FROM club_member WHERE user_id = ?", [userDataObj.user_id]);

    if (existingRegistrations.length > 0) {
      return res.status(400).json({
        status: 'registered',
        message: `ผู้ใช้รหัสประจำตัว ${userDataObj.user_id} เป็นสมาชิกชมรมนี้อยู่แล้ว`
      });
    } else if (memberofother.length > 0) {
      return res.status(400).json({
        status: 'registered',
        message: `ผู้ใช้รหัสประจำตัว ${userDataObj.user_id} เป็นสมาชิกชมรมอื่นอยู่แล้ว`
      });
    }

    await connection.query("INSERT INTO club_member (club_id, user_id) VALUES (?, ?)", [clubId, userDataObj.user_id]);

    res.status(200).json({
      status: 'ok',
      message: `ผู้ใช้รหัสประจำตัว ${userDataObj.user_id} ลงทะเบียนเข้าร่วมชมรมเรียบร้อย`
    });

  } catch (error) {
    console.error('Error registering user to the club:', error);
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});


app.get("/clubmember/:club_id", async function (req, res, next) {
  try {
    let connection = await create_connection();
    const club_id = req.params.club_id;
    let [rows] = await connection.query(
      "SELECT user.user_id,user.user_name FROM `user` JOIN club_member ON club_member.user_id=user.user_id WHERE club_member.club_id = ?",
      [club_id]
    );
    return res.json(rows);
  } catch (error) {
    console.error('Error fetching data:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get("/activitydetail/:activity_id", async function (req, res, next) {
  try {
    let connection = await create_connection();
    const activity_id = req.params.activity_id;
    let [rows] = await connection.query(
      "SELECT * FROM `activity` JOIN `activity_type` ON activity.activity_type_id = activity_type.activity_type_id WHERE activity_id = ?",
      [activity_id]
    );
    return res.json(rows);
  } catch (error) {
    console.error('Error fetching data:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/activity/:activity_id/register', jsonParser, async (req, res) => {
  try {
    const activityID = req.params.activity_id;
    const userData = req.headers['user'];

    if (!activityID || !userData) {
      throw new Error('activity ID and User data are required');
    }

    const userDataObj = JSON.parse(userData);
    const connection = await create_connection();
    const [existingRegistrations] = await connection.query("SELECT * FROM activity_paticipant WHERE activity_id = ? AND user_id = ?", [activityID, userDataObj.user_id])

    if (existingRegistrations.length > 0) {
      return res.status(400).json({
        status: 'registered',
        message: `ผู้ใช้รหัสประจำตัว ${userDataObj.user_id} ได้ลงทะเบียนเข้าร่วมกิจกรรมนี้อยู่แล้ว`
      });
    }

    await connection.query("INSERT INTO activity_paticipant (activity_id, user_id) VALUES (?, ?)", [activityID, userDataObj.user_id]);

    res.status(200).json({
      status: 'ok',
      message: `ผู้ใช้รหัสประจำตัว ${userDataObj.user_id} ลงทะเบียนเข้าร่วมกิจกรรมเรียบร้อย`
    });

  } catch (error) {
    console.error('Error registering user to the activity:', error);
    res.status(500).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

app.listen(PORT, async () => {
  console.log("CORS-enabled listening on port " + PORT);
});