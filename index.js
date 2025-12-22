require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const admin = require("firebase-admin");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const Stripe = require("stripe");

const port = process.env.PORT || 3000;
const secret = process.env.JWT_SECRET;
const isProduction = process.env.NODE_ENV === "production";

// Firebase initialization
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString("utf-8");
const serviceAccount = JSON.parse(decoded);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();

// ---------------- CORS ----------------
// ---------------- CORS ----------------
const allowedOrigins = ["http://localhost:5173", "https://chef-bazar.vercel.app"];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true); // server-to-server or Postman
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error(`CORS blocked for origin: ${origin}`));
    },
    credentials: true,
  })
);

// ✅ Handle preflight globally (fixed version)
app.use((req, res, next) => {
  if (req.method === "OPTIONS") {
    res.header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, PUT");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
    return res.sendStatus(204); // No Content
  }
  next();
});
// ---------------- Middleware ----------------
app.use(express.json());
app.use(cookieParser());

// ---------------- Stripe ----------------
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// ---------------- JWT Verification ----------------
const verifyJWT = (req, res, next) => {
  const token = req.cookies?.accessToken || req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).send({ message: "Unauthorized" });

  jwt.verify(token, secret, (err, decoded) => {
    if (err) return res.status(403).send({ message: "Forbidden" });
    req.email = decoded.email;
    req.role = decoded.role;
    next();
  });
};

// ---------------- Role Check Middleware ----------------
const verifyRole = (requiredRoles) => (req, res, next) => {
  const rolesArray = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];
  if (!req.role || !rolesArray.includes(req.role)) return res.status(403).send({ message: "Access Denied: Insufficient role" });
  next();
};

// ---------------- MongoDB Client ----------------
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

let usersCollection, mealsCollection, reviewCollection, favoritesCollection;
let orderCollection, requestsCollection, paymentHistoryCollection;

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
    paymentHistoryCollection = db.collection("payment_history");

    console.log("MongoDB connected successfully!");

    // ---------------- User APIs ----------------
    app.post("/register", async (req, res) => {
      const { email, displayName } = req.body;
      if (!email) return res.status(400).send({ message: "Email required" });

      const existing = await usersCollection.findOne({ email });
      if (existing) return res.send({ success: true });

      await usersCollection.insertOne({
        email,
        displayName: displayName || email.split("@")[0],
        role: "user",
        createdAt: new Date(),
      });

      res.send({ success: true });
    });

    app.post("/jwt", async (req, res) => {
      try {
        const { email, displayName } = req.body;
        if (!email) return res.status(400).send({ message: "Email is required" });

        let user = await usersCollection.findOne({ email });

        if (!user) {
          const newUser = {
            email,
            displayName: displayName || email.split("@")[0],
            role: "user",
            createdAt: new Date(),
          };
          const result = await usersCollection.insertOne(newUser);
          user = { _id: result.insertedId, ...newUser };
        }

        const token = jwt.sign({ email: user.email, role: user.role }, secret, { expiresIn: "30d" });

        res.cookie("accessToken", token, {
          httpOnly: true,
          secure: isProduction,
          sameSite: isProduction ? "none" : "strict",
          maxAge: 30 * 24 * 60 * 60 * 1000,
        });

        res.status(200).send({ success: true, role: user.role });
      } catch (error) {
        console.error("JWT ERROR:", error);
        res.status(500).send({ success: false, message: "Failed to generate token" });
      }
    });

    app.post("/logout", (req, res) => {
      res.clearCookie("accessToken", { httpOnly: true, secure: isProduction, sameSite: isProduction ? "none" : "strict" });
      res.send({ success: true });
    });

    app.get("/users", verifyJWT, verifyRole("admin"), async (req, res) => {
      const users = await usersCollection.find().toArray();
      res.send(users);
    });

    app.get("/users/:email", verifyJWT, async (req, res) => {
      try {
        const email = req.params.email;
        if (req.role !== "admin" && req.email !== email) return res.status(403).send({ message: "Access denied" });
        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).send({ message: "User not found" });
        res.send(user);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    app.patch("/users/update-role", verifyJWT, verifyRole("admin"), async (req, res) => {
  try {
    const { email, role, chefId } = req.body;

    if (!email || !role) {
      return res.status(400).send({ message: "Email and role are required" });
    }

    let updateDoc = {};

    if (role === "admin") {
      updateDoc = {
        $set: { role: "admin" },
        $unset: { chefId: "" },
      };
    }

    else if (role === "chef") {
      updateDoc = {
        $set: {
          role: "chef",
          chefId: chefId || `CHEF-${Date.now()}`,
        },
      };
    }

    else {
      updateDoc = {
        $set: { role },
        $unset: { chefId: "" },
      };
    }

    const result = await usersCollection.updateOne(
      { email },
      updateDoc
    );

    if (result.matchedCount === 0) {
      return res.status(404).send({ message: "User not found" });
    }

    res.send({
      success: true,
      message: `User role updated to ${role}`,
    });
  } catch (error) {
    console.error("Update role error:", error);
    res.status(500).send({ message: "Internal server error" });
  }
});


    // ---------------- Meals APIs ----------------
    app.post("/meals", verifyJWT, verifyRole("chef"), async (req, res) => {
      const meal = req.body;
      const result = await mealsCollection.insertOne(meal);
      res.status(200).send({ message: "Meal added", data: result });
    });

    app.get("/meals", async (req, res) => {
      const { page = 1, limit = 10, search = "", category = "All", sort = "" } = req.query;
      let query = {};
      if (search) query.mealName = { $regex: search, $options: "i" };
      if (category !== "All") query.foodCategory = category;

      let sortOption = {};
      if (sort === "asc") sortOption.foodPrice = 1;
      else if (sort === "desc") sortOption.foodPrice = -1;

      const skip = (parseInt(page) - 1) * parseInt(limit);
      const meals = await mealsCollection.find(query).sort(sortOption).skip(skip).limit(parseInt(limit)).toArray();
      const total = await mealsCollection.countDocuments(query);
      res.send({ meals, total });
    });

    app.get("/meals/:id", async (req, res) => {
      try {
        const meal = await mealsCollection.findOne({ _id: new ObjectId(req.params.id) });
        res.send(meal);
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: err.message });
      }
    });

    // ---------------- Orders APIs ----------------
    app.post("/orders", verifyJWT, async (req, res) => {
      try {
        const orderData = { ...req.body, userEmail: req.email };
        const result = await orderCollection.insertOne(orderData);
        res.status(201).send({ message: "Order placed", orderId: result.insertedId });
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Server Error" });
      }
    });

    app.get("/orders/user/:email", verifyJWT, async (req, res) => {
      if (req.email !== req.params.email && req.role !== "admin") return res.status(403).send({ message: "Access denied" });
      const orders = await orderCollection.find({ userEmail: req.params.email }).toArray();
      res.send(orders);
    });

    // ---------------- Payments ----------------
    app.post("/create-payment-intent", verifyJWT, async (req, res) => {
      const { amount } = req.body;
      const paymentIntent = await stripe.paymentIntents.create({
        amount: Math.round(amount * 100),
        currency: "usd",
        payment_method_types: ["card"],
      });
      res.send({ clientSecret: paymentIntent.client_secret });
    });

    app.patch("/orders/:id/pay", verifyJWT, async (req, res) => {
      const { id } = req.params;
      const { paymentInfo } = req.body;
      const order = await orderCollection.findOne({ _id: new ObjectId(id) });
      if (!order || order.userEmail !== req.email) return res.status(403).send({ message: "Access denied" });

      await orderCollection.updateOne({ _id: new ObjectId(id) }, { $set: { paymentStatus: "paid", paymentInfo } });
      await paymentHistoryCollection.insertOne({
        orderId: id,
        userEmail: order.userEmail,
        amount: order.totalPrice,
        paymentInfo,
        paymentDate: new Date(),
      });

      res.send({ success: true });
    });

    // ________________________Reviews__________________________ 

    // POST a new review
app.post("/reviews", verifyJWT, async (req, res) => {
  try {
    const reviewData = { ...req.body, userEmail: req.email, date: new Date() };
    const result = await reviewCollection.insertOne(reviewData);
    res.status(201).json({ insertedId: result.insertedId });
  } catch (err) {
    console.error("Failed to add review:", err);
    res.status(500).json({ message: "Failed to add review" });
  }
});


    app.get("/reviews/user/:email", verifyJWT, async (req, res) => {
  const email = req.params.email;
  if (email !== req.email && req.role !== "admin") {
    return res.status(403).send({ message: "Access denied" });
  }
  try {
    const userReviews = await reviewCollection.find({ userEmail: email }).sort({ date: -1 }).toArray();
    res.json(userReviews);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch user reviews" });
  }
});

// _______________________Favorites__________________
// Fetch all favorites for a user
app.get("/favorites/:email", verifyJWT, async (req, res) => {
  const email = req.params.email;

  // Only allow user to fetch their own favorites
  if (email !== req.email && req.role !== "admin") {
    return res.status(403).send({ message: "Access denied" });
  }

  try {
    const favorites = await favoritesCollection
      .find({ userEmail: email })
      .toArray();

    res.json(favorites);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to fetch favorites" });
  }
});

// Only admin can fetch all requests
app.get("/admin/requests", verifyJWT, verifyRole("admin"), async (req, res) => {
  try {
    const requests = await requestsCollection.find().toArray();
    res.status(200).json(requests);
  } catch (err) {
    console.error("Failed to fetch requests:", err);
    res.status(500).json({ message: "Failed to fetch requests" });
  }
});

 app.post("/chef-requests", async (req, res) => {
  try {
    const { userEmail, userName, requestedRole } = req.body;

    if (!userEmail || !requestedRole) {
      return res.status(400).send({ message: "Missing required fields" });
    }

    const exists = await requestsCollection.findOne({
      userEmail,
      requestType: requestedRole,
    });

    if (exists) {
      return res.send({
        alreadyRequested: true,
        message: `Already requested for ${requestedRole}`,
      });
    }

    await requestsCollection.insertOne({
      userEmail,
      userName,
      requestType: requestedRole, 
      requestStatus: "pending",
      createdAt: new Date(),
    });

    res.send({ success: true });
  } catch (err) {
    console.error("Request error:", err);
    res.status(500).send({ message: "Failed to send request" });
  }
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

    // backend/index.js
    // backend/index.js
    app.get("/admin/stats", async (req, res) => {
      try {
        const totalUsers = await usersCollection.countDocuments();
        const pendingOrders = await orderCollection.countDocuments({
          orderStatus: "pending",
        });
        const deliveredOrders = await orderCollection.countDocuments({
          orderStatus: "delivered",
        });

        const payments = await orderCollection
          .aggregate([
            { $match: { paymentStatus: "paid" } },
            { $group: { _id: null, totalAmount: { $sum: "$totalPrice" } } },
          ])
          .toArray();

        const totalPaymentAmount = payments[0]?.totalAmount || 0;

        res.send({
          totalUsers,
          pendingOrders,
          deliveredOrders,
          totalPaymentAmount,
        });
      } catch (err) {
        console.error("Admin stats error:", err);
        res.status(500).send({ error: "Server Error" });
      }
      console.log({
        totalUsers,
        pendingOrders,
        deliveredOrders,
        totalPaymentAmount,
      });
    });

    app.patch(
      "/admin/requests/:id",
      verifyJWT,
      verifyRole("admin"),
      async (req, res) => {
        try {
          const { id } = req.params;
          const { requestStatus } = req.body; // "approved" | "rejected"

          if (!ObjectId.isValid(id)) {
            return res.status(400).send({ message: "Invalid request id" });
          }

          const requestData = await requestsCollection.findOne({
            _id: new ObjectId(id),
          });

          if (!requestData) {
            return res.status(404).send({ message: "Request not found" });
          }

          if (requestStatus === "approved") {
            const { userEmail, requestType } = requestData;

            const updateDoc = {
              $set: {
                role: requestType,
              },
            };

            if (requestType === "chef") {
              updateDoc.$set.chefId =
                "chef-" + Math.floor(1000 + Math.random() * 9000);
            }

            await usersCollection.updateOne({ email: userEmail }, updateDoc);
          }

          await requestsCollection.updateOne(
            { _id: new ObjectId(id) },
            {
              $set: {
                requestStatus,
                updatedAt: new Date(),
              },
            }
          );

          res.send({
            success: true,
            message: `Request ${requestStatus} successfully.`,
          });
        } catch (err) {
          console.error(err);
          res.status(500).send({ message: "Failed to update request" });
        }
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




    // ---------------- Default ----------------
    app.get("/", (req, res) => res.send("Hello from Server!"));

    await client.db("admin").command({ ping: 1 });
    console.log("MongoDB ping successful!");
  } finally {
    // Keep connection open
  }
}

run().catch(console.dir);

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
