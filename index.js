require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const admin = require("firebase-admin");
const jwt = require("jsonwebtoken");
const port = process.env.PORT || 3000;

const secret = process.env.JWT_SECRET;


const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf-8"
);
const serviceAccount = JSON.parse(decoded);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();
// middleware
app.use(
  cors({
    origin: ["http://localhost:5173", "http://localhost:5174"],
    credentials: true,
    optionSuccessStatus: 200,
  })
);
app.use(express.json());

const verifyJWT = (req, res, next) => {
    const authorizationHeader = req.headers.authorization;
    if (!authorizationHeader) {
        return res.status(401).send({ error: true, message: 'token unavailable' });
    }
    const token = authorizationHeader.split(' ')[1];
    jwt.verify(token, secret, (err, decoded) => { 
        if (err) {
            console.error("JWT failed", err);
            return res.status(403).send({ error: true, message: 'Forbidden' }); 
        }
        
        req.decoded = decoded;
        req.email = decoded.email;
        req.role = decoded.role || "user"; 
        
        next();
    });
};
// Role check middleware
const verifyRole = (requiredRoles) => (req, res, next) => {
  if (!req.role) {
    return res.status(403).send({ message: "Access Denied: Role not found" });
  }

  const rolesArray = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];

  if (!rolesArray.includes(req.role)) {
    return res.status(403).send({ message: "Access Denied: Insufficient role" });
  }

  next();
};


// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let usersCollection;

async function run() {
  try {
    const db = client.db("mealDB");
    // user Collection
    usersCollection = db.collection('user')
    // Meals Collection
    const mealsCollection = db.collection("meals");
    // revierws Collection
    const reviewCollection = db.collection("reviews");
    // favorites Collection
    const favoritesCollection = db.collection("favorites");
    // order Collection
    const orderCollection = db.collection("order_collection");

    // user setup
    app.post("/register", async (req, res) => {
  const { email, displayName } = req.body;
  const existing = await usersCollection.findOne({ email });
  if (existing) return res.send({ message: "Already registered" });

  const result = await usersCollection.insertOne({
    email,
    displayName,
    role: "user", // default role
  });
  res.send({ result });
});

// Issue JWT after Firebase login
app.post("/jwt", async (req, res) => {
  const { email, displayName } = req.body;
  let user = await usersCollection.findOne({ email });

  if (!user) {
    // Auto-register new Google user
    const result = await usersCollection.insertOne({
      email,
      displayName: displayName || email.split("@")[0],
      role: "user",
    });
    user = { _id: result.insertedId, email, displayName, role: "user" };
  }

  const token = jwt.sign({ email, role: user.role }, process.env.JWT_SECRET, {
    expiresIn: "30d",
  });

  res.send({ token, role: user.role });
});


// Get all users (Admin only)
app.get("/users", verifyJWT, verifyRole("admin"), async (req, res) => {
  const users = await usersCollection.find().toArray();
  res.send(users);
});

// Promote / Demote user (Admin only)
app.patch("/users/:id/role", verifyJWT, verifyRole("admin"), async (req, res) => {
  try {
    const { role } = req.body; // 'user', 'seller', 'admin'
    const userId = req.params.id;

    // 1️⃣ Find user in MongoDB
    const user = await usersCollection.findOne({ _id: new ObjectId(userId) });
    if (!user) return res.status(404).send({ message: "User not found" });

    // 2️⃣ Update role in MongoDB
    await usersCollection.updateOne(
      { _id: new ObjectId(userId) },
      { $set: { role } }
    );

    // 3️⃣ Update Firebase custom claim
    // Firebase uses email to set claims
    await admin.auth().setCustomUserClaims(user.email, { role });

    res.send({ message: `User role updated to ${role}` });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to update role", error: err.message });
  }
});


// Example protected route for sellers
app.get("/seller/data", verifyJWT, verifyRole("seller"), (req, res) => {
  res.send({ secretData: "Only seller can see this" });
});

// Example protected route for users
app.get("/user/data", verifyJWT, verifyRole("user"), (req, res) => {
  res.send({ secretData: "Only normal user can see this" });
});



    // meals APIs

    app.post("/meals", async (req, res) => {
      const meal = req.body;
      const result = await mealsCollection.insertOne(meal);
      res.send(result);
    });

    app.get("/meals", async (req, res) => {
      const cursor = mealsCollection.find();
      const meals = await cursor.toArray();
      res.send(meals);
    });

    app.get("/meals/:id", async (req, res) => {
      const id = req.params.id;
      const meal = await mealsCollection.findOne({ _id: new ObjectId(id) });
      res.send(meal);
    });

    // reviews APIs
    // POST new review
    app.post("/reviews", async (req, res) => {
      try {
        const review = req.body;

        const result = await reviewCollection.insertOne(review);

        // Return full review with _id
        res.status(200).json({
          ...review,
          _id: result.insertedId.toString(),
          date: new Date(review.date).toISOString(),
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to add review" });
      }
    });

    // GET reviews by mealId
    app.get("/reviews/:mealId", async (req, res) => {
      try {
        const mealId = req.params.mealId;
        const reviews = await reviewCollection
          .find({ foodId: mealId })
          .sort({ date: -1 })
          .toArray();
        res.json(reviews);
      } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch reviews" });
      }
    });

    // DELETE review by reviewId
    app.delete("/reviews/:reviewId", async (req, res) => {
      try {
        const reviewId = req.params.reviewId;
        const result = await reviewCollection.deleteOne({
          _id: new ObjectId(reviewId),
        });
        if (result.deletedCount === 1) {
          res.status(200).json({ message: "Review deleted successfully" });
        }
      } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to delete review" });
      }
    });

    // post favorite meal
   app.post("/favorites", async (req, res) => {
  try {
    const favorite = req.body;

    const existing = await favoritesCollection.findOne({
      userEmail: favorite.userEmail,
      mealId: favorite.mealId,
    });

    if (existing) {
      return res.send({ alreadyExists: true });
    }

    // insert favorite (foodImage সহ)
    const result = await favoritesCollection.insertOne(favorite);

    res.send({
      alreadyExists: false,
      ...favorite,        // <-- এখানে foodImage থাকবে
      _id: result.insertedId.toString(),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to add favorite" });
  }
});



    // GET /favorites/:userEmail
app.get("/favorites/:userEmail", async (req, res) => {
  try {
    const userEmail = req.params.userEmail;
    const favorites = await favoritesCollection
      .find({ userEmail })
      .toArray();
    res.status(200).json(favorites);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch favorites" });
  }
});

// DELETE /favorites/:id
app.delete("/favorites/:id", async (req, res) => {
  try {
    const result = await favoritesCollection.deleteOne({
      _id: new ObjectId(req.params.id)
    });

    if (result.deletedCount === 1) {
      res.status(200).json({ message: "Favorite deleted successfully" });
    } else {
      res.status(404).json({ message: "Favorite not found" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to delete favorite" });
  }
});


// Order Api
app.post("/orders", async (req, res) => {
  try {

    const result = await orderCollection.insertOne(req.body);

    res.send({ success: true, insertedId: result.insertedId });
  } catch (error) {
    console.error(error);
    res.status(500).send({ success: false, error: "Something went wrong" });
  }
});

app.get('/orders', async (req, res) => {
  try {
    const orders = await orderCollection.find().toArray();
    res.status(200).json(orders);
  } catch (err) {
    console.error("Failed to fetch orders:", err);
    res.status(500).json({ message: "Failed to fetch orders", error: err.message });
  }
})

// Dashboard-----------------------------------------------------
// For admin

app.put('/users/:id/block', async (req, res) => {
    const userId = req.params.id;
    
    try {
        const result = await req.db.collection('users').updateOne(
            { _id: new ObjectId(userId) }, 
            // { $set: { isBlocked: true } }
        );
        if (result.modifiedCount === 1) {
            res.json({ message: `User ${userId} blocked successfully.` });
        } else {
            res.status(404).json({ message: "User not found." });
        }
    } catch (error) {
        res.status(500).json({ message: "Error blocking user.", error });
    }
});

app.get('/stats', async (req, res) => {
    try {
        const totalUsers = await req.db.collection('users').countDocuments();
        const totalOrders = await req.db.collection('orders').countDocuments();
        const totalChefs = await req.db.collection('users').countDocuments({ role: 'chef' });
        
        res.json({
            totalUsers,
            totalOrders,
            totalChefs,
        });
    } catch (error) {
        res.status(500).json({ message: "Failed to fetch statistics", error });
    }
});


// User Profile Update -----------------------------

app.put("/update-user", async (req, res) => {
  const { email, name, photo } = req.body;

  await usersCollection.updateOne(
    { email },
    { $set: { displayName: name, photoURL: photo } }
  );

  res.send({ success: true });
});





    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Hello from Server..");
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
