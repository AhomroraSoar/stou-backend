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

// app.post("/auth", authenticateJWT, (req, res, next) => {
//   const user_id = req.users.user_id;
//   connection.query(
//     "SELECT * FROM `users` WHERE `user_id` = ?",
//     [user_id],
//     function (err, results) {
//       res.json(results[0]);
//     }
//   );
// });

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
    "INSERT INTO `user`(`user_id`, `user_name`, `user_age`, `user_career`, `user_address`, `email`, `password`, `user_tel`) VALUES (?,?,?,?,?,?,?,?)",
    [
      req.body.user_id,
      req.body.user_name,
      req.body.user_age,
      req.body.user_career,
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

// CRUD user in database

app.get("/roles", async function (req, res, next) {
  let connection = await create_connection();
  let [rows] = await connection.query("SELECT * FROM `roles`");
  return res.json(rows);
});

app.get("/user", async function (req, res, next) {
  let connection = await create_connection();
  let [rows] = await connection.query(
    "SELECT * FROM user "
  );
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

// app.post("/create", async (req, res, next) => {
//   let connection = await create_connection();
//   let [results] = await connection.query(
//     "INSERT INTO `user`(`user_name`, `user_age`, `email`, `password`) VALUES (?, ?, ?, ?)",
//     [
//       req.body.user_name,
//       req.body.user_age,
//       req.body.email,
//       req.body.password,
//     ]
//   );
//   console.log(results);
//   return res.json({
//     status: "ok",
//     message:
//       "User with USER_ID : " + results.insertId + " is created successfully.",
//     results,
//   });
// });

app.put("/update", async function (req, res, next) {
  let connection = await create_connection();
  let [rows, err] = await connection.query(
    "UPDATE `users` SET `fname`= ?, `lname`= ?, `email`= ?, `password`= ?, `avatar`= ?, `contact`= ?, `role_id`= ? WHERE user_id = ?",
    [
      req.body.fname,
      req.body.lname,
      req.body.email,
      req.body.password,
      req.body.avatar,
      req.body.contact,
      req.body.role_id,
      req.body.user_id,
    ]
  );
  if (err) {
    res.json({ error: err });
  }
  const id = req.body.user_id;
  return res.json({
    status: "ok",
    message: "User with USER_ID : " + id + " is updated successfully.",
    rows,
  });
});

app.put("/updateProfile", async function (req, res, next) {
  let connection = await create_connection();
  let [rows, err] = await connection.query(
    "UPDATE `users` SET `fname`= ?, `lname`= ?, `avatar`= ?, `contact`= ? WHERE user_id = ?",
    [
      req.body.fname,
      req.body.lname,
      req.body.avatar,
      req.body.contact,
      req.body.user_id,
    ]
  );
  if (err) {
    res.json({ error: err });
  }
  const id = req.body.user_id;
  if (rows.affectedRows == 1) {
    return res.json({
      status: "ok",
      message: "User with USER_ID : " + id + " is updated successfully.",
      rows,
    });
  } else {
    return res.json({
      error: "User with USER_ID : " + id + " is not updated successfully.",
      err,
    });
  }
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

// CRUD Products
app.get("/swn", async function (req, res, next) {
  let connection = await create_connection();
  let [rows] = await connection.query("SELECT * FROM `swn`");
  return res.json(rows);
});

app.get("/swn/:swn_id", async function (req, res, next) {
  try {
    let connection = await create_connection();
    const swn_id = req.params.swn_id;
    let [rows] = await connection.query(
      "SELECT * FROM `club` WHERE club.swn_id = ?",
      [swn_id]
    );
    return res.json(rows);
  } catch (error) {
    console.error('Error fetching data:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get("/categorizedpd/:category_id", async function (req, res, next) {
  let connection = await create_connection();
  const category_id = req.params.category_id;
  let [rows] = await connection.query(
    "SELECT * FROM `products` WHERE category_id = ?",
    [category_id]
  );
  return res.json(rows);
});

app.get("/sumQuan", async function (req, res, next) {
  let connection = await create_connection();
  let [rows] = await connection.query(
    "SELECT SUM(`Quantity`) AS TotalQuantity FROM `products`"
  );

  return res.json(rows[0]);
});

app.post("/createpd", async (req, res, next) => {
  let connection = await create_connection();
  let [results] = await connection.query(
    "INSERT INTO `products`(`product_name`, `description`, `product_picture`, `Quantity`) VALUES (?, ?, ?, ?)",
    [
      req.body.product_name,
      req.body.description,
      req.body.product_picture,
      req.body.Quantity,
    ]
  );
  console.log(results);
  return res.json({
    status: "ok",
    message:
      "Product with id : " + results.insertId + " is created successfully.",
    results,
  });
});
app.put("/updatepd", async function (req, res, next) {
  let connection = await create_connection();
  let [rows, err] = await connection.query(
    "UPDATE `products` SET `product_name`= ?, `description`= ?, `product_picture`= ?, `Quantity`= ?,`category_id`= ? WHERE product_id = ?",
    [
      req.body.product_name,
      req.body.description,
      req.body.product_picture,
      req.body.Quantity,
      req.body.category_id,
      req.body.product_id,
    ]
  );
  if (err) {
    res.json({ error: err });
  }
  const id = req.body.product_id;
  return res.json({
    status: "ok",
    message: "Product with product_id : " + id + " is updated successfully.",
    rows,
  });
});
app.delete("/deletepd", async function (req, res, next) {
  let connection = await create_connection();
  let [rows, err] = await connection.query(
    "DELETE FROM `products` WHERE product_id = ?",
    [req.body.product_id]
  );
  if (err) {
    res.json({ error: err });
  }
  const id = req.body.product_id;
  return res.json({
    status: "ok",
    message: "Product with product_id : " + id + " is deleted successfully.",
    rows,
  });
});

// CRUD Category
// READ All Category
app.get("/category", async function (req, res, next) {
  let connection = await create_connection();
  let [rows] = await connection.query("SELECT * FROM `categories`");
  return res.json(rows);
});

// READ BY ID
app.get("/category/:category_id", async function (req, res, next) {
  let connection = await create_connection();
  const category_id = req.params.category_id;
  let [rows] = await connection.query(
    "SELECT * FROM `categories` WHERE `category_id` = ?",
    [category_id]
  );
  return res.json(rows[0]);
});

// CREATE Category
app.post("/createcategory", async (req, res, next) => {
  let connection = await create_connection();
  let [results] = await connection.query(
    "INSERT INTO `categories`(`category_name`, `image`) VALUES (?, ?)",
    [req.body.category_name, req.body.image]
  );
  console.log(results);
  return res.json({
    status: "ok",
    message:
      "Category with id : " + results.insertId + " is created successfully.",
    results,
  });
});

// UPDATE Category
app.put("/updatecategory", async function (req, res, next) {
  let connection = await create_connection();
  let [rows, err] = await connection.query(
    "UPDATE `categories` SET `category_name`= ?, `image`= ? WHERE category_id = ?",
    [req.body.category_name, req.body.image, req.body.category_id]
  );
  if (err) {
    res.json({ error: err });
  }
  const id = req.body.category_id;
  return res.json({
    status: "ok",
    message: "Category with category_id : " + id + " is updated successfully.",
    rows,
  });
});

// DELETE Category
app.delete("/deletecategory", async function (req, res, next) {
  let connection = await create_connection();
  let [rows, err] = await connection.query(
    "DELETE FROM `categories` WHERE category_id = ?",
    [req.body.category_id]
  );
  if (err) {
    res.json({ error: err });
  }
  const id = req.body.category_id;
  return res.json({
    status: "ok",
    message: "Category with category_id : " + id + " is deleted successfully.",
    rows,
  });
});

// CRUD Tags
// READ ALL Tags
app.get("/tags", async function (req, res, next) {
  let connection = await create_connection();
  let [rows] = await connection.query(
    "SELECT * FROM tags LEFT JOIN products ON tags.product_id = products.product_id"
  );
  return res.json(rows);
});

app.get("/connectedTags", async function (req, res, next) {
  let connection = await create_connection();
  let [rows] = await connection.query(
    "SELECT * FROM tags LEFT JOIN products ON tags.product_id = products.product_id WHERE tags.product_id IS NOT NULL"
  );
  return res.json(rows);
});
// READ BY ID
app.get("/tags/:tag_id", async function (req, res, next) {
  let connection = await create_connection();
  const tag_id = req.params.tag_id;
  let [rows] = await connection.execute(
    "SELECT * FROM `tags` WHERE `tag_id` = ?",
    [tag_id]
  );
  return res.json(rows[0]);
});
// READ BY Multi tagID
app.get("/Multags/:tag_id", async function (req, res, next) {
  let connection = await create_connection();
  const tag_id = req.params.tag_id;
  var values = "";
  values = values + "(" + tag_id + ")";
  console.log(values);
  let [rows] = await connection.execute(
    "SELECT * FROM `tags` WHERE tag_id IN " + values
  );
  return res.json(rows);
});
// CREATE Tags
app.post("/createtag", async (req, res, next) => {
  let connection = await create_connection();
  let [results] = await connection.query(
    "INSERT IGNORE INTO `tags`(`tag_detail`) VALUES (?)",
    [req.body.tag_detail]
  );
  console.log(results);
  return res.json({
    status: "ok",
    message: "Tag with id : " + results.insertId + " is created successfully.",
    results,
  });
});
// UPDATE Tags
app.put("/updatetag", async function (req, res, next) {
  let connection = await create_connection();
  let [rows, err] = await connection.query(
    "UPDATE `tags` SET `product_id`= ? WHERE tag_id = ?",
    [req.body.product_id, req.body.tag_id]
  );
  if (err) {
    res.json({ error: err });
  }
  const id = req.body.tag_id;
  return res.json({
    status: "ok",
    message: "Tag with tag_id : " + id + " is updated successfully.",
    rows,
  });
});
// UPDATE Multiple Tags
app.put("/updateMultag", async function (req, res, next) {
  const tag = req.body.tag_id;
  var values = "";
  values = values + "(" + tag + ")";
  console.log(values);
  let connection = await create_connection();

  let query = "UPDATE `tags` SET `product_id`= ? WHERE tag_id IN " + values;
  let [rows] = await connection.query(
    query,
    [req.body.product_id],
    (error, results) => {
      if (error) throw error;
      console.log(error || results);
    }
  );

  if (rows.affectedRows == 0) {
    return res.json({
      status: "error",
      message: "Tag with tag_id : " + tag + " isn't updated.",
      rows,
    });
  } else {
    return res.json({
      status: "ok",
      message: "Tag with tag_id : " + tag + " is updated successfully.",
      rows,
    });
  }
});
// DELETE Tags
app.delete("/deletetag", async function (req, res, next) {
  let connection = await create_connection();
  let [rows, err] = await connection.query(
    "DELETE FROM `tags` WHERE tag_id = ?",
    [req.body.tag_id]
  );
  if (err) {
    res.json({ error: err });
  }
  const id = req.body.tag_id;
  return res.json({
    status: "ok",
    message: "Tag with tag_id : " + id + " is deleted successfully.",
    rows,
  });
});

// DELETE Multiple Tags
app.delete("/deleteMultag", async function (req, res, next) {
  var data = req.body;
  console.log(data);
  var values = "";
  values = values + "(" + data + ")";
  console.log(values);

  let connection = await create_connection();
  let query = "DELETE FROM tags WHERE tag_id IN " + values;
  let [rows] = await connection.query(query, [], (error, results) => {
    if (error) throw error;
    console.log(error || results);
  });

  console.log(query);
  const id = req.body;
  if (rows.affectedRows == 0) {
    return res.json({
      status: "error",
      message: "Tag with tag_id : " + id + " isn't delete.",
      rows,
    });
  } else if (rows.affectedRows == 1) {
    return res.json({
      status: "ok",
      message: "Tag with tag_id : " + id + " is deleted successfully.",
      rows,
    });
  }
});

app.listen(PORT, async () => {
  console.log("CORS-enabled listening on port " + PORT);
});