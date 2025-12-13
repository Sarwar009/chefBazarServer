require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const admin = require("firebase-admin");
const jwt = require("jsonwebtoken");

const port = process.env.PORT || 3000;
const secret = process.env.JWT_SECRET;

// Firebase initialization
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf-8"
);
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
    return res.status(401).send({ error: true, message: "Token unavailable" });

  const token = authorizationHeader.split(" ")[1];
  jwt.verify(token, secret, (err, decoded) => {
    if (err) return res.status(403).send({ error: true, message: "Forbidden" });

    req.decoded = decoded;
    req.email = decoded.email;
    req.role = decoded.role || "user";
    next();
  });
};

// Role Check Middleware
const verifyRole = (requiredRoles) => (req, res, next) => {
  const rolesArray = Array.isArray(requiredRoles)
    ? requiredRoles
    : [requiredRoles];
  if (!req.role || !rolesArray.includes(req.role)) {
    return res
      .status(403)
      .send({ message: "Access Denied: Insufficient role" });
  }
  next();
};

// MongoDB Client
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let usersCollection;
let mealsCollection;
let reviewCollection;
let favoritesCollection;
let orderCollection;
let requestsCollection;

async function run() {
  try {
    const db = client.db("mealDB");

    // Collections
    usersCollection = db.collection("user");
    mealsCollection = db.collection("meals");
    reviewCollection = db.collection("reviews");
    favoritesCollection = db.collection("favorites");
    orderCollection = db.collection("order_collection");
    requestsCollection = db.collection("request");

    console.log("MongoDB connected successfully!");

    // ---------------- User APIs ----------------
    app.post("/register", async (req, res) => {
      const { email, displayName } = req.body;
      const existing = await usersCollection.findOne({ email });
      if (existing) return res.send({ message: "Already registered" });

      const result = await usersCollection.insertOne({
        email,
        displayName,
        role: "user",
      });
      res.send({ result });
    });

    app.post("/jwt", async (req, res) => {
      const { email, displayName } = req.body;
      let user = await usersCollection.findOne({ email });

      if (!user) {
        const result = await usersCollection.insertOne({
          email,
          displayName: displayName || email.split("@")[0],
          role: "user",
        });
        user = { _id: result.insertedId, email, displayName, role: "user" };
      }

      const token = jwt.sign({ email, role: user.role }, secret, {
        expiresIn: "30d",
      });
      res.send({ token, role: user.role });
    });

    app.get("/users", verifyJWT, verifyRole("admin"), async (req, res) => {
      const users = await usersCollection.find().toArray();
      res.send(users);
    });

    app.get("/users/:email", async (req, res) => {
      const user = await usersCollection.findOne({
        email: req.params.email,
      });
      res.send(user);
    });

    // server.js or routes/admin.js
    const express = require("express");
    const app = express();
    const { MongoClient, ObjectId } = require("mongodb");
    const jwt = require("jsonwebtoken"); // if using auth
    require("dotenv").config();

    app.use(express.json());

    const client = new MongoClient(process.env.MONGO_URI);
    let usersCollection, requestsCollection;

    async function initDB() {
      await client.connect();
      const db = client.db("yourDBName");
      usersCollection = db.collection("users");
      requestsCollection = db.collection("requests");
    }
    initDB();

    // Middleware to check JWT (optional)
    const verifyToken = (req, res, next) => {
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) return res.status(401).send({ error: "Unauthorized" });

      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // decoded should have email & role
        next();
      } catch (err) {
        res.status(401).send({ error: "Invalid token" });
      }
    };

    // Update user role
    app.patch("/users/update-role", verifyToken, async (req, res) => {
      try {
        const { email, role, chefId } = req.body;

        if (!email || !role) {
          return res.status(400).send({ error: "Email and role are required" });
        }

        // Update user document
        const updateData = { role };
        if (role === "chef") updateData.chefId = chefId;

        const result = await usersCollection.updateOne(
          { email },
          { $set: updateData }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ error: "User not found" });
        }

        // Update request status as approved
        await requestsCollection.updateOne(
          { userEmail: email },
          { $set: { requestStatus: "approved" } }
        );

        // Get the request to return requestedRole
        const request = await requestsCollection.findOne({ userEmail: email });

        res.send({
          success: true,
          requestedRole: request?.requestedRole || null,
          newRole: role,
          chefId: chefId || null,
        });
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Server error" });
      }
    });

    app.listen(3000, () => console.log("Server running on port 3000"));

    app.patch(
      "/users/:id/role",
      verifyJWT,
      verifyRole("admin"),
      async (req, res) => {
        try {
          const { role } = req.body;
          const userId = req.params.id;

          const user = await usersCollection.findOne({
            _id: new ObjectId(userId),
          });
          if (!user) return res.status(404).send({ message: "User not found" });

          await usersCollection.updateOne(
            { _id: new ObjectId(userId) },
            { $set: { role } }
          );
          await admin.auth().setCustomUserClaims(user.email, { role });

          res.send({ message: `User role updated to ${role}` });
        } catch (err) {
          console.error(err);
          res
            .status(500)
            .send({ message: "Failed to update role", error: err.message });
        }
      }
    );

    app.patch(
      "/users/:id/fraud",
      verifyJWT,
      verifyRole("admin"),
      async (req, res) => {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: "Invalid user id" });
        }

        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id), status: { $ne: "fraud" } },
          { $set: { status: "fraud" } }
        );

        if (result.matchedCount === 0) {
          return res
            .status(404)
            .json({ message: "User not found or already fraud" });
        }

        res.json({ message: "User marked as fraud" });
      }
    );

    app.get(
      "/admin/requests",
      verifyJWT,
      verifyRole("admin"),
      async (req, res) => {
        const requests = await requestsCollection.find().toArray();
        res.send(requests);
      }
    );

    app.patch(
      "/admin/requests/:id",
      verifyJWT,
      verifyRole("admin"),
      async (req, res) => {
        const { id } = req.params;
        const { approve } = req.body; // true / false

        const request = await Request.findById(id);
        if (!request) return res.status(404).send("Request not found");

        if (approve) {
          // Update user role
          let update = {};
          if (request.requestType === "chef") {
            update = {
              role: "chef",
              chefId: "chef-" + Math.floor(1000 + Math.random() * 9000),
            };
          } else if (request.requestType === "admin") {
            update = { role: "admin" };
          }

          await User.findOneAndUpdate({ email: request.userEmail }, update);
          request.requestStatus = "approved";
        } else {
          request.requestStatus = "rejected";
        }

        await request.save();
        res.send({ success: true, request });
      }
    );

    app.put("/update-user", async (req, res) => {
      const { email, name, photo } = req.body;
      await usersCollection.updateOne(
        { email },
        { $set: { displayName: name, photoURL: photo } }
      );
      res.send({ success: true });
    });

    // ---------------- Meals APIs ----------------
    app.post("/meals", async (req, res) => {
      const meal = req.body;
      const result = await mealsCollection.insertOne(meal);
      res
        .status(200)
        .json({ message: "Meal added successfully", data: result });
    });

    app.get("/meals", async (req, res) => {
      const meals = await mealsCollection.find().toArray();
      res.send(meals);
    });

    app.get("/meals/:id", async (req, res) => {
      try {
        const meal = await mealsCollection.findOne({
          _id: new ObjectId(req.params.id),
        });
        res.send(meal);
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: err.message });
      }
    });

    app.put("/meals/:id", verifyJWT, async (req, res) => {
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

    app.delete("/meals/:id", verifyJWT, async (req, res) => {
      try {
        const result = await mealsCollection.deleteOne({
          _id: new ObjectId(req.params.id),
        });
        res.send({ success: true, deletedCount: result.deletedCount });
      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false, error: err.message });
      }
    });

    app.get("/meals/chef/:chefId", async (req, res) => {
      const chefId = req.params.chefId;

      try {
        const orders = await mealsCollection.find({ chefId }).toArray();
        res.status(200).json(orders);
      } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch orders" });
      }
    });

    // GET my meals
    app.get("/meals/chef/:email", async (req, res) => {
      const email = req.params.email;

      const meals = await mealsCollection.find({ userEmail: email }).toArray();

      res.send(meals);
    });

    // DELETE meal
    app.delete("/meals/:id", async (req, res) => {
      const id = req.params.id;
      const result = await mealsCollection.deleteOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    // UPDATE meal
    app.patch("/meals/:id", async (req, res) => {
      const id = req.params.id;
      const updatedMeal = req.body;

      const result = await mealsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updatedMeal }
      );

      res.send(result);
    });

    // ---------------- Review APIs ----------------
    app.post("/reviews", async (req, res) => {
      try {
        const result = await reviewCollection.insertOne(req.body);
        res.send({ insertedId: result.insertedId });
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Failed to add review" });
      }
    });

    app.get("/reviews/user/:email", async (req, res) => {
      const email = req.params.email;
      try {
        const userReviews = await reviewCollection
          .find({ reviewerEmail: email })
          .toArray();
        res.send(userReviews);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Failed to load reviews" });
      }
    });

    app.get("/reviews/:mealId", async (req, res) => {
      try {
        const reviews = await reviewCollection
          .find({ foodId: req.params.mealId })
          .sort({ date: -1 })
          .toArray();
        res.json(reviews);
      } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch reviews" });
      }
    });

    app.patch("/reviews/:reviewId", verifyJWT, async (req, res) => {
      const reviewId = req.params.reviewId;
      const { rating, comment } = req.body;

      try {
        const result = await reviewCollection.updateOne(
          { _id: new ObjectId(reviewId) },
          { $set: { rating, comment, date: new Date().toISOString() } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ message: "Review not found" });
        }

        res.status(200).json({ message: "Review updated successfully" });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Failed to update review" });
      }
    });

    app.delete("/reviews/:reviewId", async (req, res) => {
      try {
        const result = await reviewCollection.deleteOne({
          _id: new ObjectId(req.params.reviewId),
        });
        res.status(200).json({
          message: "Review deleted successfully",
          deletedCount: result.deletedCount,
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to delete review" });
      }
    });

    // ---------------- Favorites APIs ----------------
    app.post("/favorites", async (req, res) => {
      try {
        const favorite = req.body;
        const existing = await favoritesCollection.findOne({
          userEmail: favorite.userEmail,
          mealId: favorite.mealId,
        });

        if (existing) return res.send({ alreadyExists: true });

        const result = await favoritesCollection.insertOne(favorite);
        res.send({
          alreadyExists: false,
          ...favorite,
          _id: result.insertedId.toString(),
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to add favorite" });
      }
    });

    app.get("/favorites/:userEmail", async (req, res) => {
      try {
        const favorites = await favoritesCollection
          .find({ userEmail: req.params.userEmail })
          .toArray();
        res.status(200).json(favorites);
      } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch favorites" });
      }
    });

    app.delete("/favorites/:id", async (req, res) => {
      try {
        const result = await favoritesCollection.deleteOne({
          _id: new ObjectId(req.params.id),
        });

        res.status(200).json({
          success: result.deletedCount === 1,
          deletedCount: result.deletedCount,
          message: "Favorite deleted successfully",
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to delete favorite" });
      }
    });

    // ---------------- Orders APIs ----------------

    // Example backend route
    app.get("/orders", async (req, res) => {
      const orders = await orderCollection.find().toArray();
      res.send(orders);
    });

    app.post("/orders", async (req, res) => {
      try {
        const result = await orderCollection.insertOne(req.body);
        res.send({ success: true, insertedId: result.insertedId });
      } catch (err) {
        console.error(err);
        res
          .status(500)
          .send({ success: false, error: "Failed to create order" });
      }
    });

    // Get all orders for a chef
    app.get("/orders/chef/:chefId", async (req, res) => {
      const chefId = req.params.chefId;

      try {
        const orders = await orderCollection.find({ chefId }).toArray();
        res.status(200).json(orders);
      } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch orders" });
      }
    });

    // Update order status
    app.patch(
      "/orders/:id/status",
      verifyJWT,
      verifyRole("chef"),
      async (req, res) => {
        const orderId = req.params.id;
        const { status } = req.body;

        if (!ObjectId.isValid(orderId)) {
          return res.status(400).json({ message: "Invalid order ID" });
        }

        try {
          const result = await orderCollection.updateOne(
            { _id: new ObjectId(orderId) },
            { $set: { orderStatus: status } }
          );

          if (result.matchedCount === 0) {
            return res.status(404).json({ message: "Order not found" });
          }

          res.status(200).json({ message: "Order status updated" });
        } catch (err) {
          console.error(err);
          res.status(500).json({ error: "Failed to update status" });
        }
      }
    );

    app.get("/orders/user/:email", async (req, res) => {
      try {
        const orders = await orderCollection
          .find({ userEmail: req.params.email })
          .toArray();
        res.send(orders);
      } catch (err) {
        console.error(err);
        res.status(500).send("Failed to load orders");
      }
    });

    app.patch("/orders/cancel/:id", async (req, res) => {
      try {
        const result = await orderCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { orderStatus: "canceled" } }
        );
        res.send(result);
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Failed to cancel order" });
      }
    });

    // ---------------- Requests APIs ----------------

    app.post("/chef-requests", async (req, res) => {
      const { userEmail, userName, requestedRole } = req.body;

      const exists = await requestsCollection.findOne({ userEmail });

      if (exists) {
        return res.send({ alreadyRequested: true });
      }

      await requestsCollection.insertOne({
        userEmail,
        userName,
        requestedRole,
        status: "pending",
        createdAt: new Date(),
      });

      res.send({ success: true });
    });

    // Admin fetch all requests
    app.get("/chef-requests", async (req, res) => {
      const requests = await requestsCollection
        .find({ status: "pending" })
        .toArray();

      res.send(requests);
    });

    app.patch("/chef-requests/:id", async (req, res) => {
      const { id } = req.params;
      const { action, userEmail } = req.body;

      if (action === "approved") {
        // Generate unique chefId
        let chefId;
        do {
          chefId = `chef-${Math.floor(1000 + Math.random() * 9000)}`;
        } while (await usersCollection.findOne({ chefId }));

        // Update user role
        await usersCollection.updateOne(
          { email: userEmail },
          {
            $set: {
              role: "chef",
              chefId,
            },
          }
        );

        // Update request status
        await requestsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status: "approved" } }
        );

        res.send({ success: true, chefId });
      }
    });

    // ---------------- Default Route ----------------
    app.get("/", (req, res) => {
      res.send("Hello from Server!");
    });

    // Ping to confirm MongoDB connection
    await client.db("admin").command({ ping: 1 });
    console.log("MongoDB ping successful!");
  } finally {
    // Keep client alive
  }
}

run().catch(console.dir);

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
