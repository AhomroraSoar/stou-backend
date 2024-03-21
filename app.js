var express = require("express");
const ldap = require("ldap-authentication");
var cors = require("cors");
var bodyParser = require("body-parser");
const sql = require("mssql");
const PORT = process.env.PORT || 4000;

var connection = {};
var app = express();
var jwt = require("jsonwebtoken");
var jsonParser = bodyParser.json();
const secret = "STOUstudentclubDevbyAhomrora(passwordencrypt)";
const bcrypt = require("bcrypt");
const saltRounds = 10;
const multer = require("multer");
const path = require("path");
const fs = require("fs");

app.use(cors());
app.use(express.json());
app.use(jsonParser);
app.use("/img-storage", express.static(path.join(__dirname, "img-storage")));

const config = {
  user: "StuAff",
  password: "@abc#123",
  server: "172.20.24.11",
  database: "StuAffDB",
  options: {
    encrypt: false,
    trustedConnection: true,
  },
};

const create_connection = async () => {
  try {
    // Create connection pool
    const pool = await sql.connect(config);

    console.log("Connected to SQL Server database successfully!");

    return pool; // Return the connection pool object
  } catch (error) {
    console.error("Error connecting to SQL Server database:", error);
  }
};

// Check connection
create_connection()
  .then((pool) => {
    // Connection is already checked inside create_connection function
    // You can perform any additional operations here if needed
    connection = pool;
  })
  .catch((err) => {
    console.error("Error creating SQL Server connection:", err);
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

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "img-storage/");
  },
  filename: function (req, file, cb) {
    cb(
      null,
      file.fieldname + "-" + Date.now() + path.extname(file.originalname)
    );
  },
});

const imageFilter = function (req, file, cb) {
  if (!file.originalname.match(/\.(jpg|jpeg|png|gif)$/)) {
    return cb(new Error("Only image files are allowed!"), false);
  }
  cb(null, true);
};

const upload = multer({ storage: storage, fileFilter: imageFilter });

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
    "SELECT * FROM `users` WHERE `email` = ?",
    [email],
    function (err, results) {
      res.json(results);
    }
  );
});

app.post("/register", jsonParser, async (req, res) => {
  let connection;
  try {
    // Create connection
    connection = await create_connection();

    const STOUemail = req.body.email;

    // Check if email already exists in the database
    let query = `SELECT STOUemail FROM users WHERE STOUemail = '${STOUemail}'`;
    let result = await connection.query(query);

    if (result.recordset.length > 0) {
      return res.status(400).json({
        status: "registered",
        message: "Email already exists in the system",
        email: email,
      });
    }

    // Hash the password
    const hash_password = await bcrypt.hash(req.body.password, saltRounds);

    // Insert new user into the database
    query = `
    INSERT INTO users (user_id, name, user_age, user_career, department, program, user_address, email, password, user_tel) 
    VALUES (
      '${req.body.user_id}',
      '${req.body.name}',
      ${req.body.user_age},
      '${req.body.user_career}',
      '${req.body.department}',
      '${req.body.program}',
      '${req.body.user_address}',
      '${email}',
      '${hash_password}',
      '${req.body.user_tel}'
    )`;

    result = await connection.query(query);

    if (result.rowsAffected[0] === 1) {
      return res.status(200).json({
        status: "ok",
        message: "User registered successfully",
        user_id: req.body.user_id, // Use the provided user_id
      });
    } else {
      throw new Error("User registration failed");
    }
  } catch (error) {
    console.error("Error during registration:", error);
    return res
      .status(500)
      .json({ status: "error", message: "Internal server error" });
  } finally {
    // Close connection
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error("Error closing connection:", error);
      }
    }
  }
});

//
app.post("/loginAD", jsonParser, async function (req, res, next) {
  let connection;
  try {
    const ldapConfig = {
      ldapOpts: {
        url: "ldap://202.28.103.39",
        reconnect: true,
      },
      userDn: req.body.username,
      userPassword: req.body.password,
    };

    let auth = false;
    try {
      auth = await ldap.authenticate(ldapConfig);
      console.log("LDAP Authentication:", auth);
    } catch (ldapError) {
      console.error("LDAP Authentication Error:", ldapError.message);
    }

    if (auth) {
      const token = jwt.sign({ username: req.body.username }, secret, {
        expiresIn: "1h",
      });

      connection = await create_connection();

      const query = `
        SELECT users.user_id, users.name,users.role_id FROM users 
        JOIN department ON users.department_id = department.department_id 
        WHERE STOUemail = @username
      `;

      const result = await connection
        .request()
        .input("username", sql.VarChar, req.body.username)
        .query(query);

      if (result.recordset.length === 0) {
        return res
          .status(404)
          .json({ status: "error", message: "User not found in database" });
      }

      const userData = result.recordset[0];

      return res.json({
        status: "success",
        message: "LDAP authentication successful",
        token: token,
        userData: userData,
      });
    } else {
      if (!connection) {
        connection = await create_connection();
      }

      const result = await connection.query`
        SELECT users.user_id,users.STOUemail, users.password, users.name FROM users WHERE [STOUemail] = ${req.body.username}
      `;
      const userData = result.recordset[0];

      if (userData.length === 0) {
        return res.json({
          status: "error",
          message: "Email not found in the system",
        });
      }

      const match = await bcrypt.compare(req.body.password, userData.password);
      if (match) {
        const token = jwt.sign({ username: userData.STOUemail }, secret, {
          expiresIn: "1h",
        });
        return res.json({
          status: "success",
          message: "Welcome",
          token,
          userData: userData,
        });
      } else {
        return res.json({ status: "error", message: "Invalid password" });
      }
    }
  } catch (error) {
    console.error("Error during login:", error);
    return res
      .status(500)
      .json({ status: "error", message: "Internal server error" });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error("Error closing connection:", error);
      }
    }
  }
});

// app.post("/login", jsonParser, async function (req, res, next) {
//   let connection;
//   try {
//     connection = await create_connection();

//     const result =
//       await connection.query`SELECT * FROM users WHERE [email] = ${req.body.email}`;
//     const user = result.recordset;

//     if (user.length === 0) {
//       return res.json({
//         status: "error",
//         message: "Email not found in the system",
//       });
//     }

//     const match = await bcrypt.compare(req.body.password, user[0].password);
//     if (match) {
//       const token = jwt.sign({ email: user[0].email }, secret, {
//         expiresIn: "1h",
//       });
//       return res.json({
//         status: "success",
//         message: "Welcome",
//         token,
//         user: user[0],
//       });
//     } else {
//       return res.json({ status: "error", message: "Invalid password" });
//     }
//   } catch (error) {
//     console.error("Error during login:", error);
//     return res
//       .status(500)
//       .json({ status: "error", message: "Internal server error" });
//   } finally {

//     if (connection) {
//       try {
//         await connection.close();
//       } catch (error) {
//         console.error("Error closing connection:", error);
//       }
//     }
//   }
// });

app.post("/reset-password", jsonParser, async (req, res) => {
  let connection;
  const { email, newPassword } = req.body;

  try {
    // Create connection
    connection = await create_connection();

    // Check if the email exists in the database
    const result =
      await connection.query`SELECT * FROM users WHERE [email] = ${email}`;
    const rows = result.recordset;

    // If the email does not exist, return an error
    if (rows.length === 0) {
      return res.status(404).json({
        status: "error",
        message: "Email not found in the system",
      });
    }

    // Hash the new password before updating the database
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update the user's password in the database
    await connection.query`UPDATE [users] SET [password] = ${hashedPassword} WHERE [email] = ${email}`;

    // Send a success response
    res.status(200).json({ status: "ok" });
  } catch (error) {
    console.error("Error resetting password:", error);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    // Close connection
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error("Error closing connection:", error);
      }
    }
  }
});

app.get("/swn", async function (req, res, next) {
  let connection;
  try {
    connection = await create_connection();

    const result = await connection.query`SELECT * FROM [swn]`;
    const rows = result.recordset;

    return res.json(rows);
  } catch (error) {
    console.error('Error fetching data from "swn" table:', error);
    return res.status(500).json({ error: "Internal server error" });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error("Error closing connection:", error);
      }
    }
  }
});

app.get("/teacherlist", async function (req, res) {
  try {
    // Create connection
    let connection = await create_connection();

    // Query to fetch teacher list along with club information
    let query = `
    SELECT club_advisor.advisor_id, club_advisor.advisor_name, club_advisor.department, club_advisor.advisor_tel, club_advisor.line_contact, club.club_name
    FROM club_advisor
    JOIN club ON club_advisor.club_id = club.club_id;
    
    `;

    // Execute the query
    let result = await connection.query(query);

    // Send response with the fetched rows
    return res.json(result.recordset);
  } catch (error) {
    console.error("Error fetching teacher list:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/swn/:swn_id", async function (req, res, next) {
  try {
    const swn_id = req.params.swn_id;
    const query = `
      SELECT * FROM club 
      JOIN swn ON club.swn_id = swn.swn_id 
      WHERE club.swn_id = @swn_id
    `;
    const connection = await create_connection(); // Assuming 'create_connection()' returns an active connection

    const result = await connection
      .request()
      .input("swn_id", sql.Int, swn_id)
      .query(query);

    return res.json(result.recordset);
  } catch (error) {
    console.error("Error fetching data:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/club/:club_id", async function (req, res, next) {
  try {
    // Assuming you already have a connection object named 'connection'
    const connection = await create_connection(); // Assuming 'create_connection()' returns an active connection

    const club_id = req.params.club_id;
    const query = `
      SELECT * FROM activity 
      JOIN club ON activity.club_id = club.club_id 
      WHERE activity.club_id = @club_id
    `;

    const result = await connection
      .request()
      .input("club_id", sql.Int, club_id)
      .query(query);

    // No need to close the connection if it's managed elsewhere in your code

    return res.json(result.recordset);
  } catch (error) {
    console.error("Error fetching data:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/clubname/:club_id", async function (req, res, next) {
  try {
    const club_id = req.params.club_id;
    const query = `
      SELECT * FROM club WHERE club_id = @club_id
    `;

    // Assuming you already have a connection object named 'connection'
    const connection = await create_connection(); // Assuming 'create_connection()' returns an active connection

    const result = await connection
      .request()
      .input("club_id", sql.Int, club_id)
      .query(query);

    // No need to close the connection if it's managed elsewhere in your code

    return res.json(result.recordset[0]);
  } catch (error) {
    console.error("Error fetching data:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/activity/:activity_id", async function (req, res, next) {
  try {
    const activity_id = req.params.activity_id;
    const query = `
      SELECT users.user_id, users.name, activity.club_id 
      FROM users
      JOIN activity_participants ON activity_participants.user_id = users.user_id 
      JOIN activity ON activity_participants.activity_id = activity.activity_id 
      WHERE activity_participants.activity_id = @activity_id
    `;

    // Assuming you already have a connection object named 'connection'
    const connection = await create_connection(); // Assuming 'create_connection()' returns an active connection

    const result = await connection
      .request()
      .input("activity_id", sql.Int, activity_id)
      .query(query);

    // No need to close the connection if it's managed elsewhere in your code

    return res.json(result.recordset);
  } catch (error) {
    console.error("Error fetching data:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/club/:club_id/teacher", async function (req, res, next) {
  try {
    const club_id = req.params.club_id;
    const query = `
      SELECT advisor_id, advisor_name, department, advisor_tel, line_contact
      FROM club_advisor
      WHERE club_id = @club_id
    `;

    // Assuming you already have a connection object named 'connection'
    const connection = await create_connection(); // Assuming 'create_connection()' returns an active connection

    const result = await connection
      .request()
      .input("club_id", sql.Int, club_id)
      .query(query);

    // No need to close the connection if it's managed elsewhere in your code

    return res.json(result.recordset);
  } catch (error) {
    console.error("Error fetching data:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/club/:club_id/committee", async function (req, res, next) {
  try {
    const club_id = req.params.club_id;
    const query = `
      SELECT club_committee.committee_id,club_committee.committee_name, club_committee.committee_tel, club_committee.committee_line , committee_role.committee_role_name
      FROM club_committee 
      JOIN committee_role ON club_committee.committee_role_id = committee_role.committee_role_id  
      WHERE club_committee.club_id = @club_id
    `;

    // Assuming you already have a connection object named 'connection'
    const connection = await create_connection(); // Assuming 'create_connection()' returns an active connection

    const result = await connection
      .request()
      .input("club_id", sql.Int, club_id)
      .query(query);

    // No need to close the connection if it's managed elsewhere in your code

    return res.json(result.recordset);
  } catch (error) {
    console.error("Error fetching data:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/club/:club_id/register", jsonParser, async (req, res) => {
  try {
    const clubId = req.params.club_id;
    const userDataHeader = req.headers["user"];

    if (!clubId || !userDataHeader) {
      throw new Error("Club ID and User data are required");
    }

    const userData = JSON.parse(userDataHeader);

    const connection = await create_connection();

    const request = connection.request();
    request.input("club_id", sql.Int, clubId);
    request.input("user_id", sql.VarChar, userData.user_id); // Adjust type to VARCHAR

    const existingRegistrationsResult = await request.query(
      "SELECT * FROM club_member WHERE club_id = @club_id AND user_id = @user_id"
    );
    const memberOfOtherResult = await request.query(
      "SELECT * FROM club_member WHERE user_id = @user_id"
    );

    const existingRegistrations = existingRegistrationsResult.recordset;
    const memberOfOther = memberOfOtherResult.recordset;

    if (existingRegistrations.length > 0) {
      return res.status(400).json({
        status: "registered",
        message: `User with ID ${userData.user_id} is already a member of this club`,
      });
    } else if (memberOfOther.length > 0) {
      return res.status(400).json({
        status: "registered",
        message: `User with ID ${userData.user_id} is already a member of another club`,
      });
    }

    await request.query(
      "INSERT INTO club_member (club_id, user_id) VALUES (@club_id, @user_id)"
    );

    res.status(200).json({
      status: "ok",
      message: `User with ID ${userData.user_id} successfully registered to the club`,
    });
  } catch (error) {
    console.error("Error registering user to the club:", error);
    res.status(500).json({
      status: "error",
      message: "Internal server error",
    });
  }
});

app.get("/clubmember/:club_id", async function (req, res, next) {
  try {
    const club_id = req.params.club_id;
    const query = `
      SELECT users.user_id, users.name 
      FROM users 
      JOIN club_member ON club_member.user_id = users.user_id 
      WHERE club_member.club_id = @club_id
    `;
    const connection = await create_connection(); // Assuming 'create_connection()' returns an active connection

    const result = await connection
      .request()
      .input("club_id", sql.Int, club_id)
      .query(query);

    return res.json(result.recordset);
  } catch (error) {
    console.error("Error fetching data:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/activitydetail/:activity_id", async function (req, res, next) {
  try {
    const activity_id = req.params.activity_id;
    const query = `
      SELECT * 
      FROM activity 
      JOIN activity_type ON activity.activity_type_id = activity_type.activity_type_id 
      WHERE activity_id = @activity_id
    `;
    const connection = await create_connection(); // Assuming 'create_connection()' returns an active connection

    const result = await connection
      .request()
      .input("activity_id", sql.Int, activity_id)
      .query(query);

    return res.json(result.recordset);
  } catch (error) {
    console.error("Error fetching data:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/activity/:activity_id/register", jsonParser, async (req, res) => {
  try {
      const activityID = req.params.activity_id;
      const userData = req.headers["user"];

      if (!activityID) {
          throw new Error("Activity ID is required");
      } else if (!userData) {
          throw new Error("User data not detected");
      }

      const userDataObj = JSON.parse(userData);

      // Check if user_id is present and valid
      // if (!userDataObj || !userDataObj.user_id || typeof userDataObj.user_id !== 'string') {
      //     throw new Error("Invalid user ID");
      // }

      const user_id = userDataObj.user_id.toString();
      console.log(user_id);

      const connection = await create_connection();

      // Create a new request object
      const request = connection.request();

      // Bind parameters
      request.input("activityID", sql.Int, activityID);
      request.input("user_id", sql.VarChar, user_id); // Adjust data type as needed

      // Check if the user is already registered for the activity
      const result = await request.query(
          "SELECT * FROM activity_participants WHERE activity_id = @activityID AND user_id = @user_id"
      );

      if (result.recordset.length > 0) {
          return res.status(400).json({
              status: "registered",
              message: `User with ID ${user_id} is already registered for this activity`,
          });
      }

      // Insert the user as a participant for the activity
      await request.query(
          "INSERT INTO activity_participants (activity_id, user_id) VALUES (@activityID, @user_id)"
      );

      res.status(200).json({
          status: "ok",
          message: `User with ID ${user_id} successfully registered for the activity`,
      });
  } catch (error) {
      console.error("Error registering user to the activity:", error);
      res.status(500).json({
          status: "error",
          message: "Internal server error",
      });
  }
});



app.post("/createswn", async (req, res) => {
  let connection;
  try {
    // Create connection
    connection = await create_connection();

    const swn_name = req.body.swn_name;

    // Check if swn_name already exists in the database
    let query = `SELECT swn_name FROM swn WHERE swn_name = '${swn_name}'`;
    let result = await connection.query(query);

    if (result.length > 0) {
      return res.status(400).json({
        status: "registered",
        message: "This SWN already exists in the system",
        swn_name: swn_name,
      });
    }

    query = `
      INSERT INTO swn (swn_name) 
      VALUES ('${req.body.swn_name}')
    `;

    result = await connection.query(query);

    if (result.rowsAffected[0] === 1) {
      return res.status(200).json({
        status: "ok",
        message: "เพิ่มศูนย์วิทยบริการและชุมชนสัมพันธ์เรียบร้อยแล้ว",
      });
    } else {
      throw new Error("Failed to add SWN");
    }
  } catch (error) {
    console.error("Error adding SWN:", error);
    return res
      .status(500)
      .json({ status: "error", message: "Internal server error" });
  } finally {
    // Close connection
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error("Error closing connection:", error);
      }
    }
  }
});

app.post("/updateswn", jsonParser, async (req, res) => {
  let connection;
  const { swn_id, swn_name } = req.body;

  try {
    // Create connection
    connection = await create_connection();

    // Check if the swn_id exists in the database
    const result =
      await connection.query`SELECT * FROM swn WHERE [swn_id] = ${swn_id}`;
    const rows = result.recordset;

    // If the swn_id does not exist, return an error
    if (rows.length === 0) {
      return res.status(404).json({
        status: "error",
        message: "swn_id not found in the system",
      });
    }

    // Update the swn_name in the database
    await connection.query`UPDATE [swn] SET [swn_name] = ${swn_name} WHERE [swn_id] = ${swn_id}`;

    // Send a success response
    res.status(200).json({ status: "ok" });
  } catch (error) {
    console.error("Error updating swn_name:", error);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    // Close connection
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error("Error closing connection:", error);
      }
    }
  }
});

app.delete("/deleteswn", async function (req, res, next) {
  let connection;
  try {
    connection = await create_connection();
    const request = connection.request();
    request.input("swn_id", req.body.swn_id);

    const result = await request.query(
      "DELETE FROM swn WHERE swn_id = @swn_id"
    );

    return res.json({
      status: "ok",
      message: "ลบศูนย์วิทยาบริการและชุมชนสัมพันธ์เรียบร้อย",
      rows: result.rowsAffected[0],
    });
  } catch (error) {
    console.error("Error deleting SWN:", error);
    return res.status(500).json({ error: "Internal server error" });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error("Error closing connection:", error);
      }
    }
  }
});

app.post("/createclub/:swn_id", async (req, res) => {
  let connection;
  try {
    // Create connection
    connection = await create_connection();

    const club_name = req.body.club_name;
    const swn_id = req.params.swn_id;

    // Check if swn_name already exists in the database
    let query = `SELECT club_name FROM club WHERE club_name = '${club_name}'`;
    let result = await connection.query(query);

    if (result.length > 0) {
      return res.status(400).json({
        status: "registered",
        message: "This club already exists in the system",
        club_name: club_name,
      });
    }

    query = `
      INSERT INTO club (club_name,swn_id) 
      VALUES ('${club_name}',${swn_id})
    `;

    result = await connection.query(query);

    if (result.rowsAffected[0] === 1) {
      return res.status(200).json({
        status: "ok",
        message: "เพิ่มชมรมเรียบร้อยแล้ว",
      });
    } else {
      throw new Error("Failed to add club");
    }
  } catch (error) {
    console.error("Error adding club:", error);
    return res
      .status(500)
      .json({ status: "error", message: "Internal server error" });
  } finally {
    // Close connection
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error("Error closing connection:", error);
      }
    }
  }
});

app.post("/updateclub", jsonParser, async (req, res) => {
  let connection;
  const { club_id, club_name } = req.body;

  try {
    // Create connection
    connection = await create_connection();

    // Check if the swn_id exists in the database
    const result =
      await connection.query`SELECT * FROM club WHERE [club_id] = ${club_id}`;
    const rows = result.recordset;

    // If the swn_id does not exist, return an error
    if (rows.length === 0) {
      return res.status(404).json({
        status: "error",
        message: "club not found in the system",
      });
    }

    // Update the swn_name in the database
    await connection.query`UPDATE [club] SET [club_name] = ${club_name} WHERE [club_id] = ${club_id}`;

    // Send a success response
    res.status(200).json({ status: "ok" });
  } catch (error) {
    console.error("Error updating club_name:", error);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    // Close connection
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error("Error closing connection:", error);
      }
    }
  }
});

app.delete("/deleteclub", async function (req, res) {
  let connection;
  try {
    connection = await create_connection();
    const request = connection.request();
    request.input("club_id", req.body.club_id);

    const result = await request.query(
      "DELETE FROM club WHERE club_id = @club_id"
    );

    return res.json({
      status: "ok",
      message: "ลบชมรมเรียบร้อย",
      rows: result.rowsAffected[0],
    });
  } catch (error) {
    console.error("Error deleting Club:", error);
    return res.status(500).json({ error: "Internal server error" });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error("Error closing connection:", error);
      }
    }
  }
});

app.post("/createactivity/:club_id", async (req, res) => {
  let connection;
  try {
    // Create connection
    connection = await create_connection();

    const {
      activity_name,
      location,
      province,
      start_date,
      finish_date,
      facebook_contact,
      line_contact,
      activity_type_id,
    } = req.body;

    const club_id = req.params.club_id;

    const checkQuery = `SELECT activity_name FROM activity WHERE activity_name = @activity_name`;
    const checkRequest = new sql.Request(connection);
    checkRequest.input("activity_name", sql.VarChar, activity_name);
    const checkResult = await checkRequest.query(checkQuery);

    if (checkResult.recordset.length > 0) {
      return res.status(400).json({
        status: "registered",
        message: "This activity already exists in the system",
        activity_name: activity_name,
      });
    }

    const insertQuery = `
      INSERT INTO activity 
      (activity_name, location, province, start_date, finish_date, facebook_contact, line_contact, activity_type_id, club_id) 
      VALUES (@activity_name, @location, @province, @start_date, @finish_date, @facebook_contact, @line_contact, @activity_type_id, @club_id)
    `;

    const insertRequest = new sql.Request(connection);
    insertRequest.input("activity_name", sql.VarChar, activity_name);
    insertRequest.input("location", sql.VarChar, location);
    insertRequest.input("province", sql.VarChar, province);
    insertRequest.input("start_date", sql.DateTime, start_date);
    insertRequest.input("finish_date", sql.DateTime, finish_date);
    insertRequest.input("facebook_contact", sql.VarChar, facebook_contact);
    insertRequest.input("line_contact", sql.VarChar, line_contact);
    insertRequest.input("activity_type_id", sql.Int, activity_type_id);
    insertRequest.input("club_id", sql.Int, club_id);

    const insertResult = await insertRequest.query(insertQuery);

    if (insertResult.rowsAffected[0] === 1) {
      return res.status(200).json({
        status: "ok",
        message: "Activity added successfully",
      });
    } else {
      throw new Error("Failed to add activity");
    }
  } catch (error) {
    console.error("Error adding activity:", error);
    return res
      .status(500)
      .json({ status: "error", message: "Internal server error" });
  } finally {
    // Close connection
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error("Error closing connection:", error);
      }
    }
  }
});

app.get("/activity_type", async function (req, res) {
  let connection;
  try {
    connection = await create_connection();

    const result = await connection.query`SELECT * FROM [activity_type]`;
    const rows = result.recordset;

    return res.json(rows);
  } catch (error) {
    console.error('Error fetching data from "activity_type" table:', error);
    return res.status(500).json({ error: "Internal server error" });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error("Error closing connection:", error);
      }
    }
  }
});

app.put("/updateactivity/:activity_id", jsonParser, async (req, res) => {
  let connection;
  const {
    activity_name,
    location,
    province,
    start_date,
    finish_date,
    facebook_contact,
    line_contact,
    activity_type_id,
  } = req.body;

  const { activity_id } = req.params;

  try {
    connection = await create_connection();

    const checkQuery = `SELECT activity_id FROM activity WHERE activity_id = @activity_id`;
    const checkRequest = new sql.Request(connection);
    checkRequest.input("activity_id", sql.Int, activity_id);
    const checkResult = await checkRequest.query(checkQuery);

    if (checkResult.recordset.length === 0) {
      return res.status(404).json({
        status: "not_found",
        message: "Activity not found",
        activity_id: activity_id,
      });
    }

    const updateQuery = `
      UPDATE activity 
      SET 
        activity_name = @activity_name,
        location = @location,
        province = @province,
        start_date = @start_date,
        finish_date = @finish_date,
        facebook_contact = @facebook_contact,
        line_contact = @line_contact,
        activity_type_id = @activity_type_id
      WHERE
        activity_id = @activity_id
    `;

    const updateRequest = new sql.Request(connection);
    updateRequest.input("activity_id", sql.Int, activity_id);
    updateRequest.input("activity_name", sql.VarChar, activity_name);
    updateRequest.input("location", sql.VarChar, location);
    updateRequest.input("province", sql.VarChar, province);
    updateRequest.input("start_date", sql.DateTime, start_date);
    updateRequest.input("finish_date", sql.DateTime, finish_date);
    updateRequest.input("facebook_contact", sql.VarChar, facebook_contact);
    updateRequest.input("line_contact", sql.VarChar, line_contact);
    updateRequest.input("activity_type_id", sql.Int, activity_type_id);

    await updateRequest.query(updateQuery);

    // Send a success response
    res.status(200).json({ status: "ok" });
  } catch (error) {
    console.error("Error updating activity:", error);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    // Close connection
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error("Error closing connection:", error);
      }
    }
  }
});

app.delete("/deleteactivity", async function (req, res) {
  let connection;
  try {
    connection = await create_connection();
    const request = connection.request();
    request.input("activity_id", req.body.activity_id);

    const result = await request.query(
      "DELETE FROM activity WHERE activity_id = @activity_id"
    );

    return res.json({
      status: "ok",
      message: "ลบกิจกรรมเรียบร้อย",
      rows: result.rowsAffected[0],
    });
  } catch (error) {
    console.error("Error deleting Club:", error);
    return res.status(500).json({ error: "Internal server error" });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error("Error closing connection:", error);
      }
    }
  }
});

app.get("/clublist", async function (req, res) {
  let connection;
  try {
    connection = await create_connection();

    const result = await connection.query`SELECT * FROM [club]`;
    const rows = result.recordset;

    return res.json(rows);
  } catch (error) {
    console.error('Error fetching data from "committee_role" table:', error);
    return res.status(500).json({ error: "Internal server error" });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error("Error closing connection:", error);
      }
    }
  }
});

app.post("/advisorregister", jsonParser, async (req, res) => {
  let connection;
  try {
    // Create connection
    connection = await create_connection();

    const advisor_id = req.body.advisor_id;

    let query = `SELECT advisor_id FROM club_advisor WHERE advisor_id = '${advisor_id}'`;
    let result = await connection.query(query);

    if (result.recordset.length > 0) {
      return res.status(400).json({
        status: "registered",
        message: "This advisor already exists in the system",
        advisor_id: advisor_id,
      });
    }

    query = `
    INSERT INTO club_advisor (advisor_id, advisor_name, department, advisor_tel, line_contact,club_id) 
    VALUES (
      '${req.body.advisor_id}',
      '${req.body.advisor_name}',
      '${req.body.department}',
      '${req.body.advisor_tel}',
      '${req.body.line_contact}',
      '${req.body.club_id}'
    )`;

    result = await connection.query(query);

    if (result.rowsAffected[0] === 1) {
      return res.status(200).json({
        status: "ok",
        message: "Advisor registered successfully",
        advisor_id: req.body.advisor_id,
      });
    } else {
      throw new Error("User registration failed");
    }
  } catch (error) {
    console.error("Error during registration:", error);
    return res
      .status(500)
      .json({ status: "error", message: "Internal server error" });
  } finally {
    // Close connection
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error("Error closing connection:", error);
      }
    }
  }
});

app.post("/advisorregister/club/:club_id", jsonParser, async (req, res) => {
  let connection;
  try {
    // Create connection
    connection = await create_connection();

    const { club_id } = req.params;
    const advisor_id = req.body.advisor_id;

    // Check if email already exists in the database
    let query = `SELECT advisor_id FROM club_advisor WHERE advisor_id = '${advisor_id}'`;
    let result = await connection.query(query);

    if (result.recordset.length > 0) {
      return res.status(400).json({
        status: "registered",
        message: "user already exists in the system",
        advisor_id: advisor_id,
      });
    }

    // Insert new user into the database
    query = `
    INSERT INTO club_advisor (advisor_id, advisor_name, department, advisor_tel, line_contact,club_id) 
    VALUES (
      '${req.body.advisor_id}',
      '${req.body.advisor_name}',
      '${req.body.department}',
      '${req.body.advisor_tel}',
      '${req.body.line_contact}',
      '${club_id}'
    )`;

    result = await connection.query(query);

    if (result.rowsAffected[0] === 1) {
      return res.status(200).json({
        status: "ok",
        message: "User registered successfully",
        advisor_id: req.body.advisor_id, // Use the provided user_id
      });
    } else {
      throw new Error("User registration failed");
    }
  } catch (error) {
    console.error("Error during registration:", error);
    return res
      .status(500)
      .json({ status: "error", message: "Internal server error" });
  } finally {
    // Close connection
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error("Error closing connection:", error);
      }
    }
  }
});

app.post("/committeeregister", jsonParser, async (req, res) => {
  let connection;
  try {
    connection = await create_connection();

    const committee_name = req.body.committee_name;

    let query = `SELECT committee_name FROM club_committee WHERE committee_name = '${committee_name}'`;
    let result = await connection.query(query);

    if (result.recordset.length > 0) {
      return res.status(400).json({
        status: "registered",
        message: "This committee already exists in the system",
        committee_name: committee_name,
      });
    }

    query = `
    INSERT INTO club_committee ( committee_name, committee_tel,committee_line,committee_role_id,club_id) 
    VALUES (
      '${req.body.committee_name}',
      '${req.body.committee_tel}',
      '${req.body.committee_line}',
      '${req.body.committee_role_id}',
      '${req.body.club_id}'
    )`;

    result = await connection.query(query);

    if (result.rowsAffected[0] === 1) {
      return res.status(200).json({
        status: "ok",
        message: "User registered successfully",
        committee_name: req.body.committee_name,
      });
    } else {
      throw new Error("User registration failed");
    }
  } catch (error) {
    console.error("Error during registration:", error);
    return res
      .status(500)
      .json({ status: "error", message: "Internal server error" });
  } finally {
    // Close connection
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error("Error closing connection:", error);
      }
    }
  }
});

app.post("/committeeregister/club/:club_id", jsonParser, async (req, res) => {
  let connection;
  try {
    // Create connection
    connection = await create_connection();

    const { club_id } = req.params;
    const committee_name = req.body.committee_name;

    let query = `SELECT committee_name FROM club_committee WHERE committee_name = '${committee_name}'`;
    let result = await connection.query(query);

    if (result.recordset.length > 0) {
      return res.status(400).json({
        status: "registered",
        message: "This committee already exists in the system",
        committee_name: committee_name,
      });
    }

    query = `
    INSERT INTO club_committee ( committee_name, committee_tel,committee_line,committee_role_id,club_id) 
    VALUES (
      '${req.body.committee_name}',
      '${req.body.committee_tel}',
      '${req.body.committee_line}',
      '${req.body.committee_role_id}',
      '${club_id}'
    )`;

    result = await connection.query(query);

    if (result.rowsAffected[0] === 1) {
      return res.status(200).json({
        status: "ok",
        message: "User registered successfully",
        committee_name: req.body.committee_name, // Use the provided user_id
      });
    } else {
      throw new Error("User registration failed");
    }
  } catch (error) {
    console.error("Error during registration:", error);
    return res
      .status(500)
      .json({ status: "error", message: "Internal server error" });
  } finally {
    // Close connection
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error("Error closing connection:", error);
      }
    }
  }
});

app.get("/committee_role", async function (req, res) {
  let connection;
  try {
    connection = await create_connection();

    const result = await connection.query`SELECT * FROM [committee_role]`;
    const rows = result.recordset;

    return res.json(rows);
  } catch (error) {
    console.error('Error fetching data from "committee_role" table:', error);
    return res.status(500).json({ error: "Internal server error" });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error("Error closing connection:", error);
      }
    }
  }
});

app.post(
  "/pictureupload/:activity_id",
  upload.single("picture"),
  async (req, res) => {
    try {
      const { activity_id } = req.params;

      if (!req.file) {
        return res.status(400).json({ error: "No file uploaded" });
      }

      await sql.connect(config);

      const pictureUrl = `http://localhost:${PORT}/${req.file.path}`;
      const request = new sql.Request();
      request.input("img_url", sql.NVarChar, pictureUrl);
      request.input("activity_id", sql.Int, activity_id);
      await request.query(
        "INSERT INTO img_storage (img_url, activity_id) VALUES (@img_url, @activity_id)"
      );

      res.json({ img_url: pictureUrl });
    } catch (error) {
      console.error("Error uploading picture:", error);
      res.status(500).json({ error: "Internal server error" });
    } finally {
      sql.close();
    }
  }
);

app.get("/images/:activity_id", async (req, res) => {
  const { activity_id } = req.params;

  try {
    connection = await create_connection();

    const result = await connection
      .request()
      .input("activity_id", sql.Int, activity_id)
      .query(
        "SELECT img_id, img_url FROM img_storage WHERE activity_id = @activity_id"
      );

    const images = result.recordset;

    res.json(images);
  } catch (error) {
    console.error("Error fetching images:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.delete("/deleteimage/:img_id", async function (req, res, next) {
  let connection;
  try {
    connection = await create_connection();
    const request = connection.request();
    const img_id = req.params.img_id;

    const getimageUrl = `SELECT img_url FROM img_storage WHERE img_id = @img_id`;
    const imageUrlResult = await request
      .input("img_id", img_id)
      .query(getimageUrl);
    const imageUrl = imageUrlResult.recordset[0].img_url;

    const relativePath = imageUrl.split("http://localhost:4000")[1];

    const deleteimageQuery = `DELETE FROM img_storage WHERE img_id = @img_id`;
    const deleteResult = await request.query(deleteimageQuery);

    const imagePath = path.join(__dirname, relativePath);
    fs.unlinkSync(imagePath);

    return res.json({
      status: "ok",
      message: "ลบรูปภาพเรียบร้อย",
      rows: deleteResult.rowsAffected[0],
    });
  } catch (error) {
    console.error("Error deleting image:", error);
    return res.status(500).json({ error: "Internal server error" });
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (error) {
        console.error("Error closing connection:", error);
      }
    }
  }
});

app.listen(PORT, async () => {
  console.log("CORS-enabled listening on port " + PORT);
});
