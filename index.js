require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');

const port = process.env.PORT || 3000;
const secret = process.env.JWT_SECRET;

// Firebase initialization
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf-8');
const serviceAccount = JSON.parse(decoded);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// JWT Verification
const verifyJWT = (req, res, next) => {
  const authorizationHeader = req.headers.authorization;
  if (!authorizationHeader)
    return res.status(401).send({ error: true, message: 'Token unavailable' });

  const token = authorizationHeader.split(' ')[1];
  jwt.verify(token, secret, (err, decoded) => {
    if (err) return res.status(403).send({ error: true, message: 'Forbidden' });

    req.decoded = decoded;
    req.email = decoded.email;
    req.role = decoded.role || 'user';
    next();
  });
};

// Role Check Middleware
const verifyRole = (requiredRoles) => (req, res, next) => {
  const rolesArray = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];
  if (!req.role || !rolesArray.includes(req.role)) {
    return res.status(403).send({ message: 'Access Denied: Insufficient role' });
  }
  next();
};

// MongoDB Client
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

let usersCollection;
let mealsCollection;
let reviewCollection;
let favoritesCollection;
let orderCollection;
let requestsCollection;

async function run() {
  try {
    const db = client.db('mealDB');

    // Collections
    usersCollection = db.collection('user');
    mealsCollection = db.collection('meals');
    reviewCollection = db.collection('reviews');
    favoritesCollection = db.collection('favorites');
    orderCollection = db.collection('order_collection');
    requestsCollection = db.collection('request');

    console.log('MongoDB connected successfully!');

    // ---------------- User APIs ----------------
    app.post('/register', async (req, res) => {
      const { email, displayName } = req.body;
      const existing = await usersCollection.findOne({ email });
      if (existing) return res.send({ message: 'Already registered' });

      const result = await usersCollection.insertOne({ email, displayName, role: 'user' });
      res.send({ result });
    });

    app.post('/jwt', async (req, res) => {
      const { email, displayName } = req.body;
      let user = await usersCollection.findOne({ email });

      if (!user) {
        const result = await usersCollection.insertOne({
          email,
          displayName: displayName || email.split('@')[0],
          role: 'user',
        });
        user = { _id: result.insertedId, email, displayName, role: 'user' };
      }

      const token = jwt.sign({ email, role: user.role }, secret, { expiresIn: '30d' });
      res.send({ token, role: user.role });
    });

    app.get('/users', verifyJWT, verifyRole('admin'), async (req, res) => {
      const users = await usersCollection.find().toArray();
      res.send(users);
    });

    app.patch('/users/:id/role', verifyJWT, verifyRole('admin'), async (req, res) => {
      try {
        const { role } = req.body;
        const userId = req.params.id;

        const user = await usersCollection.findOne({ _id: new ObjectId(userId) });
        if (!user) return res.status(404).send({ message: 'User not found' });

        await usersCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { role } });
        await admin.auth().setCustomUserClaims(user.email, { role });

        res.send({ message: `User role updated to ${role}` });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: 'Failed to update role', error: err.message });
      }
    });

    app.put('/update-user', async (req, res) => {
      const { email, name, photo } = req.body;
      await usersCollection.updateOne({ email }, { $set: { displayName: name, photoURL: photo } });
      res.send({ success: true });
    });

    // ---------------- Meals APIs ----------------
    app.post('/meals', async (req, res) => {
      const meal = req.body;
      const result = await mealsCollection.insertOne(meal);
      res.status(200).json({ message: 'Meal added successfully', data: result });
    });

    app.get('/meals', async (req, res) => {
      const meals = await mealsCollection.find().toArray();
      res.send(meals);
    });

    app.get('/meals/:id', async (req, res) => {
      try {
        const meal = await mealsCollection.findOne({ _id: new ObjectId(req.params.id) });
        res.send(meal);
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: err.message });
      }
    });

    app.put('/meals/:id', verifyJWT, async (req, res) => {
      try {
        const result = await mealsCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: req.body }
        );
        res.send({ success: true, modifiedCount: result.modifiedCount });
      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false, error: err.message });
      }
    });

    app.delete('/meals/:id', verifyJWT, async (req, res) => {
      try {
        const result = await mealsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        res.send({ success: true, deletedCount: result.deletedCount });
      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false, error: err.message });
      }
    });

    app.get('/meals/chef/:chefId', async (req, res) => {
      const meals = await mealsCollection.find({ chefId: req.params.chefId }).toArray();
      res.send(meals);
    });

    // ---------------- Review APIs ----------------
    app.post('/reviews', async (req, res) => {
      try {
        const result = await reviewCollection.insertOne(req.body);
        res.send({ insertedId: result.insertedId });
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: 'Failed to add review' });
      }
    });

    app.get('/reviews/user/:email', async (req, res) => {
      const email = req.params.email;
      try {
        const userReviews = await reviewCollection.find({ reviewerEmail: email }).toArray();
        res.send(userReviews);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: 'Failed to load reviews' });
      }
    });

    app.get('/reviews/:mealId', async (req, res) => {
      try {
        const reviews = await reviewCollection.find({ foodId: req.params.mealId }).sort({ date: -1 }).toArray();
        res.json(reviews);
      } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch reviews' });
      }
    });


    app.patch('/reviews/:reviewId', verifyJWT, async (req, res) => {
  const reviewId = req.params.reviewId;
  const { rating, comment } = req.body;

  try {
    const result = await reviewCollection.updateOne(
      { _id: new ObjectId(reviewId) },
      { $set: { rating, comment, date: new Date().toISOString() } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: 'Review not found' });
    }

    res.status(200).json({ message: 'Review updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to update review' });
  }
});

    app.delete('/reviews/:reviewId', async (req, res) => {
      try {
        const result = await reviewCollection.deleteOne({ _id: new ObjectId(req.params.reviewId) });
        res.status(200).json({ message: 'Review deleted successfully', deletedCount: result.deletedCount });
      } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to delete review' });
      }
    });

    // ---------------- Favorites APIs ----------------
    app.post('/favorites', async (req, res) => {
      try {
        const favorite = req.body;
        const existing = await favoritesCollection.findOne({
          userEmail: favorite.userEmail,
          mealId: favorite.mealId,
        });

        if (existing) return res.send({ alreadyExists: true });

        const result = await favoritesCollection.insertOne(favorite);
        res.send({ alreadyExists: false, ...favorite, _id: result.insertedId.toString() });
      } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to add favorite' });
      }
    });

    app.get('/favorites/:userEmail', async (req, res) => {
      try {
        const favorites = await favoritesCollection.find({ userEmail: req.params.userEmail }).toArray();
        res.status(200).json(favorites);
      } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch favorites' });
      }
    });

    app.delete('/favorites/:id', async (req, res) => {
      try {
        const result = await favoritesCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        if (result.deletedCount === 1) res.status(200).json({ message: 'Favorite deleted successfully' });
        else res.status(404).json({ message: 'Favorite not found' });
      } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to delete favorite' });
      }
    });

    // ---------------- Orders APIs ----------------
    app.post('/orders', async (req, res) => {
      try {
        const result = await orderCollection.insertOne(req.body);
        res.send({ success: true, insertedId: result.insertedId });
      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false, error: 'Failed to create order' });
      }
    });

    app.get('/orders/user/:email', async (req, res) => {
      try {
        const orders = await orderCollection.find({ userEmail: req.params.email }).toArray();
        res.send(orders);
      } catch (err) {
        console.error(err);
        res.status(500).send('Failed to load orders');
      }
    });

    app.patch('/orders/cancel/:id', async (req, res) => {
      try {
        const result = await orderCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { orderStatus: 'canceled' } }
        );
        res.send(result);
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: 'Failed to cancel order' });
      }
    });

    // ---------------- Requests APIs ----------------
    app.post('/requests', verifyJWT, async (req, res) => {
      try {
        const result = await requestsCollection.insertOne(req.body);
        res.send({ success: true, insertedId: result.insertedId });
      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false, error: err.message });
      }
    });

    app.get('/requests', verifyJWT, verifyRole('admin'), async (req, res) => {
      try {
        const requests = await requestsCollection.find().toArray();
        res.send(requests);
      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false, error: err.message });
      }
    });

    app.patch('/requests/:id', verifyJWT, verifyRole('admin'), async (req, res) => {
      try {
        const id = req.params.id;
        const { action } = req.body;
        const request = await requestsCollection.findOne({ _id: new ObjectId(id) });
        if (!request) return res.status(404).send({ message: 'Request not found' });

        await requestsCollection.updateOne({ _id: new ObjectId(id) }, { $set: { requestStatus: action } });

        if (action === 'approved') {
          const roleUpdate = request.requestType === 'chef' ? 'chef' : 'admin';
          const chefId = roleUpdate === 'chef' ? `chef-${Math.floor(1000 + Math.random() * 9000)}` : null;
          await usersCollection.updateOne({ email: request.userEmail }, { $set: { role: roleUpdate, chefId } });
        }

        res.send({ success: true, action });
      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false, error: err.message });
      }
    });

    // ---------------- Default Route ----------------
    app.get('/', (req, res) => {
      res.send('Hello from Server!');
    });

    // Ping to confirm MongoDB connection
    await client.db('admin').command({ ping: 1 });
    console.log('MongoDB ping successful!');
  } finally {
    // Keep client alive
  }
}

run().catch(console.dir);

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
