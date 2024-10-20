import mysql from 'mysql2/promise';
import { parse } from 'url';
import { sign, verify } from 'jsonwebtoken';
import { authMiddleware } from '../../utils/authMiddleware';
import bcrypt from 'bcrypt';

const db = mysql.createPool({
  host: process.env.MYSQL_HOST,
  port: process.env.MYSQL_PORT,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

export default async function handler(req, res) {
  const { method } = req;
  const { pathname } = parse(req.url, true);

  try {
    switch (method) {
      case 'GET':
        if (pathname === '/api/check-auth') {
          return handleCheckAuth(req, res);
        } else if (pathname === '/api/login') {
          return authMiddleware(handleGetLogin)(req, res);
        } else if (pathname === '/api/signup') {
          return handleGetSignup(req, res);
        } else if (pathname === '/api/acustomer') {
          return authMiddleware(handleGetCustomers)(req, res);
        }
        break;

      case 'POST':
        if (pathname === '/api/login') {
          return handleLogIn(req, res);
        } else if (pathname === '/api/validate-pin') {
          return handleValidatePin(req, res);
        } else if (pathname === '/api/logout') {
          return handleLogout(req, res);
        } else if (pathname === '/api/acustomer') {
          return authMiddleware(handleAddCustomer)(req, res);
        } else if (pathname === '/api/orders') {
          return handleGetOrders(req, res); // Get orders
        } else if (pathname === '/api/signup') {
          return handlePostSignup(req, res);
        }
        break;

      case 'PUT':
        if (pathname.startsWith('/api/aproduct/')) {
          const id = pathname.split('/').pop();
          await handleUpdateProduct(req, res, id);
        } else if (pathname.startsWith('/api/acustomer/')) {
          const customerId = pathname.split('/').pop();
          await handleUpdateCustomer(req, res, customerId);
        } else if (pathname === '/api/orders') {
          return handleAddOrder(req, res); // Add order
        }
        break;

      case 'DELETE':
        if (pathname.startsWith('/api/aproduct/')) {
          const id = pathname.split('/').pop();
          await handleDeleteProduct(req, res, id);
        } else if (pathname.startsWith('/api/acustomer/')) {
          const customerId = pathname.split('/').pop();
          await handleDeleteCustomer(req, res, customerId);
        }
        break;

      default:
        res.setHeader('Allow', ['GET', 'POST', 'PUT', 'DELETE']);
        res.status(405).end(`Method ${method} Not Allowed`);
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred while processing your request' });
  }
}

// Authentication
function handleCheckAuth(req, res) {
  const token = req.cookies.token;

  if (!token) {
    return res.status(200).json({ isAuthenticated: false });
  }

  try {
    verify(token, process.env.JWT_SECRET);
    return res.status(200).json({ isAuthenticated: true });
  } catch (error) {
    return res.status(200).json({ isAuthenticated: false });
  }
}

// Login
async function handleLogIn(req, res) {
  const { emailaddress, password } = req.body;
  const [result] = await db.query('SELECT * FROM acustomer WHERE emailaddress = ?', [emailaddress]);

  if (result.length === 0 || !(await bcrypt.compare(password, result[0].password))) {
    return res.status(401).json({ error: 'Invalid emailaddress or password' });
  }

  const user = result[0];
  const token = sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.setHeader('Set-Cookie', `token=${token}; HttpOnly; Path=/; Max-Age=3600; SameSite=Strict`);
  res.status(200).json({ success: true, message: 'Signin successful', emailaddress: user.emailaddress });
}

// Logout
function handleLogout(req, res) {
  res.setHeader('Set-Cookie', 'token=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict');
  res.status(200).json({ success: true, message: 'Logout successful' });
}

// Signup
async function handlePostSignup(req, res) {
  const { fullname, contactnumber, emailaddress, password } = req.body;

  // Perform basic validation
  if (!fullname || !contactnumber || !emailaddress || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  // Check if the user already exists
  try {
    const [existingUser] = await db.query('SELECT * FROM acustomer WHERE emailaddress = ?', [emailaddress]);
    if (existingUser.length > 0) {
      return res.status(409).json({ error: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert a new user into the database
    const [result] = await db.query(
      'INSERT INTO acustomer (fullname, contactnumber, emailaddress, password) VALUES (?, ?, ?, ?)',
      [fullname, phoneNumber, emailaddress, hashedPassword]
    );

    res.status(201).json({ success: true, message: 'Signup successful', userId: result.insertId });
  } catch (error) {
    console.error("Error during signup:", error);
    res.status(500).json({ error: 'An error occurred while creating the user' });
  }
}

// Other functions (handleGetCustomers, handleAddOrder, etc.) would go here