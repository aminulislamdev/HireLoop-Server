import express from 'express';
import cors from 'cors';
import 'dotenv/config'
import { MongoClient } from 'mongodb';

// Create an instance of the Express application
const app = express();
const port =process.env.PORT || 8000;


// Middleware
app.use(cors());
app.use(express.json());


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


// Routes
app.get('/', (req, res) => {
  res.send('Hello World!');
});

// get all users
app.get('/users', async (req, res) => {
  const cursor = usersCollection.find({});
  const users = await cursor.toArray();
  res.send(users);
});



app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});