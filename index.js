import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import 'dotenv/config'
import { MongoClient, ObjectId } from 'mongodb';

// Create an instance of the Express application
const app = express();
const port = process.env.PORT || 8000;

// CORS options: allow the Next.js client to call this API and send cookies
// cross-origin. Cookies are required so the client can forward its Better
// Auth session. This object is attached to each route below (no app.use).
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:3000';
const corsOptions = { origin: CLIENT_ORIGIN, credentials: true };

// database connection
const uri = process.env.DB_URL;
if (!uri) {
  console.error("DB_URL is missing from the server environment.");
  process.exit(1);
}

const client = new MongoClient(uri);

export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.error("Failed to connect to MongoDB:", err);
    throw err;
  }
}

const connectedClient = await connectToMongoDB();
const db = connectedClient.db('hireloop');
const usersCollection = db.collection('user');
const jobsCollection = db.collection('jobs');
// Better Auth stores its active sessions here (token, userId, expiresAt).
const sessionsCollection = db.collection('session');

// ---- Helpers ---------------------------------------------------------------

// Tiny cookie parser so we don't need the cookie-parser package.
// Returns an object like { "better-auth.session_token": "abc123" }.
function parseCookies(req) {
  const header = req.headers.cookie || '';
  const cookies = {};
  header.split(';').forEach((part) => {
    const index = part.indexOf('=');
    if (index === -1) return;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (name) cookies[name] = decodeURIComponent(value);
  });
  return cookies;
}

// Wraps an async route handler so unexpected errors answer with a clean
// JSON message instead of a crash or an HTML error page.
function handleErrors(handler) {
  return async (req, res) => {
    try {
      await handler(req, res);
    } catch (err) {
      console.error(err);
      if (!res.headersSent) {
        res.status(500).json({ message: 'Something went wrong on the server.' });
      }
    }
  };
}

// Better Auth signs its session cookie value as "<token>.<hmac-signature>"
// (URL-encoded) but stores only the raw token in the database. Strip the
// signature part before the lookup. This is safe because session tokens are
// random strings over a-zA-Z0-9 and never contain a "." themselves.
function extractSessionToken(cookieValue) {
  const decoded = decodeURIComponent(cookieValue);
  const dotIndex = decoded.indexOf('.');
  return dotIndex === -1 ? decoded : decoded.slice(0, dotIndex);
}

// ---- Middleware (attached per route, not globally) --------------------------

// Checks the "Authorization: Bearer <token>" header and saves the decoded
// payload on req.user for the route handlers below.
function verifyToken(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ message: 'Missing authentication token.' });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }
}

// After verifyToken, make sure the token belongs to a recruiter.
function requireRecruiter(req, res, next) {
  if (req.user?.role !== 'recruiter') {
    return res.status(403).json({ message: 'Only recruiters can post jobs.' });
  }
  next();
}

// ---- Routes ----------------------------------------------------------------

app.get('/', cors(corsOptions), (req, res) => {
  res.send('Hello World!');
});

// get all users
app.get('/users', cors(corsOptions), handleErrors(async (req, res) => {
  const cursor = usersCollection.find({});
  const users = await cursor.toArray();
  res.send(users);
}));

/**
 * Exchanges a verified Better Auth session for our own short-lived JWT.
 *
 * The client cannot be trusted to tell us who it is (email alone would be
 * easy to fake), so we read the httpOnly Better Auth session cookie, check
 * the matching session row in MongoDB, load the user behind it and only then
 * sign a token with the verified data: userId, name, email and role.
 */
app.post('/auth/token', cors(corsOptions), handleErrors(async (req, res) => {
  const cookies = parseCookies(req);
  // "secure" deployments prefix the cookie with __Secure-; accept both.
  const sessionToken =
    cookies['better-auth.session_token'] ||
    cookies['__Secure-better-auth.session_token'];

  if (!sessionToken) {
    return res.status(401).json({ message: 'No Better Auth session found. Please sign in first.' });
  }

  // 1. The session must exist and not be expired. The cookie value may carry
  // a HMAC signature ("<token>.<signature>"), so strip it before matching.
  const session = await sessionsCollection.findOne({
    token: extractSessionToken(sessionToken),
  });
  if (!session || new Date(session.expiresAt) <= new Date()) {
    return res.status(401).json({ message: 'Your session has expired. Please sign in again.' });
  }

  // 2. The user behind the session must still exist.
  const user = await usersCollection.findOne({ _id: session.userId });
  if (!user) {
    return res.status(401).json({ message: 'User account no longer exists.' });
  }

  // 3. Only recruiters may receive a job-posting token.
  if (user.role !== 'recruiter') {
    return res.status(403).json({ message: 'Only recruiters can post jobs.' });
  }

  // 4. Sign the token with the VERIFIED session data (never client input).
  const token = jwt.sign(
    {
      userId: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.send({ token });
}));

// Preflight support for the routes the browser talks to.
app.options('/auth/token', cors(corsOptions));
app.options('/jobs', cors(corsOptions));

// Create a job (recruiters only, authenticated with a Bearer token).
// express.json() is attached here per route to parse the JSON request body.
app.post('/jobs', cors(corsOptions), express.json(), verifyToken, requireRecruiter, handleErrors(async (req, res) => {
  const {
    title,
    companyName,
    category,
    jobType,
    isRemote,
    location,
    deadline,
    salaryMin,
    salaryMax,
    salaryFrequency,
    responsibilities,
    requirements,
  } = req.body;

  // Simple required-field validation.
  const missing = [];
  if (!title) missing.push('title');
  if (!companyName) missing.push('companyName');
  if (!category) missing.push('category');
  if (!jobType) missing.push('jobType');
  if (!location) missing.push('location');
  if (!responsibilities) missing.push('responsibilities');
  if (!requirements) missing.push('requirements');

  if (missing.length > 0) {
    return res.status(400).json({
      message: `Missing required fields: ${missing.join(', ')}`,
    });
  }

  const job = {
    title,
    companyName,
    category,
    jobType,
    isRemote: Boolean(isRemote),
    location,
    deadline: deadline || null,
    salary: {
      min: Number(salaryMin) || null,
      max: Number(salaryMax) || null,
      frequency: salaryFrequency || 'per year',
    },
    responsibilities,
    requirements,
    // Recruiter identity comes from the verified token, not the request body.
    recruiter: {
      userId: req.user.userId,
      name: req.user.name,
      email: req.user.email,
      role: req.user.role,
    },
    createdAt: new Date(),
  };

  const result = await jobsCollection.insertOne(job);
  res.status(201).send({
    message: 'Job posted successfully.',
    jobId: result.insertedId,
  });
}));

// Get all jobs (public, newest first).
app.get('/jobs', cors(corsOptions), handleErrors(async (req, res) => {
  const jobs = await jobsCollection.find({}).sort({ createdAt: -1 }).toArray();
  res.send(jobs);
}));

// Get one job by id (public).
app.get('/jobs/:id', cors(corsOptions), handleErrors(async (req, res) => {
  const { id } = req.params;

  // Guard against invalid ids so findOne never throws.
  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ message: 'Invalid job id.' });
  }

  const job = await jobsCollection.findOne({ _id: new ObjectId(id) });
  if (!job) {
    return res.status(404).json({ message: 'Job not found.' });
  }
  res.send(job);
}));

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
