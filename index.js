require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const admin = require("firebase-admin");
const port = process.env.PORT || 3000;
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

// jwt middlewares
const verifyJWT = async (req, res, next) => {
  const token = req?.headers?.authorization?.split(" ")[1];
  console.log(token);
  if (!token) return res.status(401).send({ message: "Unauthorized Access!" });
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.tokenEmail = decoded.email;
    console.log(decoded);
    next();
  } catch (err) {
    console.log(err);
    return res.status(401).send({ message: "Unauthorized Access!", err });
  }
};

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
async function run() {
  try {
    const db = client.db("mealDB");
    // Meals Collection
    const mealsCollection = db.collection("meals");
    // revierws Collection
    const reviewCollection = db.collection("reviews");
    // favorites Collection
    const favoritesCollection = db.collection("favorites");


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
