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
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf-8"
);
const serviceAccount = JSON.parse(decoded);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();

// ---------------- CORS ----------------
const allowedOrigins = [
  "https://chef-bazar.vercel.app",
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true); // server-to-server or Postman
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error(`CORS blocked for origin: ${origin}`));
  },
  credentials: true,
}));


app.use((req, res, next) => {
  if (req.method === "OPTIONS") {
    res.header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, PUT");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
    return res.sendStatus(204);
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
  const token =
    req.cookies?.accessToken || req.headers["authorization"]?.split(" ")[1];
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
  const rolesArray = Array.isArray(requiredRoles)
    ? requiredRoles
    : [requiredRoles];
  if (!req.role || !rolesArray.includes(req.role))
    return res
      .status(403)
      .send({ message: "Access Denied: Insufficient role" });
  next();
};

// ---------------- MongoDB Client ----------------
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const generateChefId = async () => {
  let chefId;
  let exists = true;

  while (exists) {
    chefId = `chef-${Math.floor(1000 + Math.random() * 9000)}`;
    const user = await usersCollection.findOne({ chefId });
    if (!user) exists = false;
  }

  return chefId;
};

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
        if (!email)
          return res.status(400).send({ message: "Email is required" });

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

        const token = jwt.sign({ email: user.email, role: user.role }, secret, {
          expiresIn: "30d",
        });

        res.cookie("accessToken", token, {
          httpOnly: true,
          secure: true, // because Vercel is HTTPS
          sameSite: "none", // cross-site
          maxAge: 30 * 24 * 60 * 60 * 1000,
        });

        res.status(200).send({ success: true, role: user.role });
      } catch (error) {
        console.error("JWT ERROR:", error);
        res
          .status(500)
          .send({ success: false, message: "Failed to generate token" });
      }
    });

    app.post("/logout", (req, res) => {
      res.clearCookie("accessToken", {
        httpOnly: true,
        secure: isProduction,
        sameSite: isProduction ? "none" : "strict",
      });
      res.send({ success: true });
    });

    app.get("/users", verifyJWT, verifyRole("admin"), async (req, res) => {
      const users = await usersCollection.find().toArray();
      res.send(users);
    });

    app.get("/users/:email", verifyJWT, async (req, res) => {
      try {
        const email = req.params.email; // requested email
        console.log("Requested email:", email);
        console.log("JWT email:", req.email, "Role:", req.role);

        // Check access: admin can fetch any user, else user can fetch only self
        if (!req.role)
          return res.status(403).send({ message: "Role missing in token" });
        if (req.role !== "admin" && req.email !== email) {
          return res.status(403).send({ message: "Access denied" });
        }

        // Fetch user from MongoDB
        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }

        res.status(200).send(user);
      } catch (err) {
        console.error("User fetch error:", err);
        res.status(500).send({ message: "Internal server error" });
      }
    });

    app.patch(
      "/users/update-role",
      verifyJWT,
      verifyRole("admin"),
      async (req, res) => {
        try {
          const { email, role } = req.body;

          if (!email || !role) {
            return res.status(400).send({ message: "Email & role required" });
          }

          const updateDoc = { $set: { role } };

          // ✅ user → chef
          if (role === "chef") {
            const chefId = await generateChefId();
            updateDoc.$set.chefId = chefId;
          }

          // ✅ chef → admin (chefId remove)
          if (role === "admin") {
            updateDoc.$unset = { chefId: "" };
          }

          const result = await usersCollection.updateOne({ email }, updateDoc);

          if (result.matchedCount === 0) {
            return res.status(404).send({ message: "User not found" });
          }

          res.send({
            success: true,
            message: `Role updated to ${role}`,
          });
        } catch (error) {
          console.error("Role update error:", error);
          res.status(500).send({ message: "Internal server error" });
        }
      }
    );

    // ---------------- Meals APIs ----------------
    app.post("/meals", verifyJWT, verifyRole("chef"), async (req, res) => {
      const meal = req.body;
      const result = await mealsCollection.insertOne(meal);
      res.status(200).send({ message: "Meal added", data: result });
    });

    app.get("/meals", async (req, res) => {
      try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const search = req.query.search || "";
        const category = req.query.category || "All";
        const sortOrder = req.query.sort || ""; // "asc" or "desc"

        const query = {};

        // Search by meal name
        if (search) {
          query.foodName = { $regex: search, $options: "i" }; // <-- make sure field name matches DB
        }

        // Filter by category
        if (category && category !== "All") {
          query.foodCategory = category;
        }

        // Total count for pagination
        const total = await mealsCollection.countDocuments(query);

        // Sorting
        let cursor = mealsCollection.find(query);
        if (sortOrder === "asc") cursor = cursor.sort({ price: 1 });
        else if (sortOrder === "desc") cursor = cursor.sort({ price: -1 });

        // Pagination
        const meals = await cursor
          .skip((page - 1) * limit)
          .limit(limit)
          .toArray();

        res.status(200).json({ meals, total });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Failed to fetch meals" });
      }
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

    // UPDATE MEAL (Chef only)
    app.patch("/meals/:id", verifyJWT, async (req, res) => {
      try {
        const { id } = req.params;
        const updatedMeal = req.body;

        const meal = await mealsCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!meal) {
          return res.status(404).send({ message: "Meal not found" });
        }

        // ✅ Admin can update anything
        if (req.role !== "admin") {
          // ✅ Chef can update only own meal
          if (meal.userEmail !== req.email) {
            return res.status(403).send({ message: "Forbidden" });
          }
        }

        const result = await mealsCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              ...updatedMeal,
              updatedAt: new Date(),
            },
          }
        );

        res.send({
          success: true,
          message: "Meal updated successfully",
          modifiedCount: result.modifiedCount,
        });
      } catch (error) {
        console.error("Update meal error:", error);
        res.status(500).send({ message: "Failed to update meal" });
      }
    });

    app.delete("/meals/:id", verifyJWT, async (req, res) => {
      try {
        const { id } = req.params;

        const meal = await mealsCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!meal) {
          return res.status(404).send({ message: "Meal not found" });
        }

        // ✅ Admin can delete anything
        if (req.role !== "admin") {
          // ✅ Chef can delete only own meal
          if (meal.userEmail !== req.email) {
            return res.status(403).send({ message: "Forbidden" });
          }
        }

        await mealsCollection.deleteOne({ _id: new ObjectId(id) });

        res.send({
          success: true,
          message: "Meal deleted successfully",
        });
      } catch (error) {
        console.error("Delete meal error:", error);
        res.status(500).send({ message: "Failed to delete meal" });
      }
    });

    // Get meals by chefId
    app.get("/meals/chef/:chefId", async (req, res) => {
      try {
        const { chefId } = req.params;

        if (!chefId) {
          return res.status(400).json({ message: "ChefId is required" });
        }

        const meals = await mealsCollection
          .find({ chefId })
          .sort({ createdAt: -1 })
          .toArray();

        res.status(200).json(meals);
      } catch (err) {
        console.error("Failed to fetch chef meals:", err);
        res.status(500).json({ message: "Failed to fetch meals" });
      }
    });

    // ---------------- Orders APIs ----------------
    app.post("/orders", verifyJWT, async (req, res) => {
      try {
        const orderData = { ...req.body, userEmail: req.email };
        const result = await orderCollection.insertOne(orderData);
        res
          .status(201)
          .send({ message: "Order placed", orderId: result.insertedId });
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Server Error" });
      }
    });

    app.get("/orders/user/:email", verifyJWT, async (req, res) => {
      if (req.email !== req.params.email && req.role !== "admin")
        return res.status(403).send({ message: "Access denied" });
      const orders = await orderCollection
        .find({ userEmail: req.params.email })
        .toArray();
      res.send(orders);
    });

    // ================= CHEF ORDERS =================
    app.get(
      "/orders/chef/:chefId",
      verifyJWT,
      verifyRole("chef"),
      async (req, res) => {
        try {
          const chefId = req.params.chefId;

          if (!chefId) {
            return res.status(400).send({ message: "ChefId required" });
          }

          const orders = await orderCollection
            .find({ chefId })
            .sort({ orderTime: -1 })
            .toArray();

          res.send(orders);
        } catch (error) {
          console.error("Chef orders error:", error);
          res.status(500).send({ message: "Failed to fetch chef orders" });
        }
      }
    );

    // ================= UPDATE ORDER STATUS (CHEF) =================
    app.patch(
      "/orders/:id/status",
      verifyJWT,
      verifyRole("chef"),
      async (req, res) => {
        try {
          const { id } = req.params;
          const { status } = req.body;

          if (!status) {
            return res.status(400).send({ message: "Status is required" });
          }

          const result = await orderCollection.updateOne(
            { _id: new ObjectId(id) },
            {
              $set: {
                orderStatus: status,
                updatedAt: new Date(),
              },
            }
          );

          if (result.matchedCount === 0) {
            return res.status(404).send({ message: "Order not found" });
          }

          res.send({
            success: true,
            message: "Order status updated",
          });
        } catch (error) {
          console.error("Order status update error:", error);
          res.status(500).send({ message: "Failed to update order status" });
        }
      }
    );

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
      if (!order || order.userEmail !== req.email)
        return res.status(403).send({ message: "Access denied" });

      await orderCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { paymentStatus: "paid", paymentInfo } }
      );
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

    app.get("/reviews", async (req, res) => {
      try {
        const reviews = await reviewCollection
          .find()
          .sort({ date: -1 })
          .toArray();

        res.status(200).json(reviews);
      } catch (err) {
        console.error("Failed to fetch reviews:", err);
        res.status(500).json({ message: "Failed to fetch reviews" });
      }
    });

    // POST a new review
    app.post("/reviews", verifyJWT, async (req, res) => {
      try {
        const reviewData = {
          ...req.body,
          userEmail: req.email,
          date: new Date(),
        };
        const result = await reviewCollection.insertOne(reviewData);
        res.status(201).json({ insertedId: result.insertedId });
      } catch (err) {
        console.error("Failed to add review:", err);
        res.status(500).json({ message: "Failed to add review" });
      }
    });

    // GET /reviews/:mealId
    app.get("/reviews/:mealId", async (req, res) => {
  try {
    const mealId = req.params.mealId;

    if (!mealId) {
      return res.status(400).json({ message: "Meal ID is required" });
    }

    const reviews = await reviewCollection
      .find({ foodId: mealId })
      .sort({ date: -1 }) // latest first
      .toArray();

    res.status(200).json(reviews);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to fetch reviews" });
  }
});


    // DELETE a review by ID
    app.delete("/reviews/:id", async (req, res) => {
      try {
        const reviewId = req.params.id;

        if (!reviewId) {
          return res.status(400).json({ message: "Review ID is required" });
        }

        const result = await reviewCollection.deleteOne({
          _id: new ObjectId(reviewId),
        });

        if (result.deletedCount === 0) {
          return res.status(404).json({ message: "Review not found" });
        }

        res.status(200).json({ message: "Review deleted successfully" });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Failed to delete review" });
      }
    });

    app.get("/reviews/user/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;
      if (email !== req.email && req.role !== "admin") {
        return res.status(403).send({ message: "Access denied" });
      }
      try {
        const userReviews = await reviewCollection
          .find({ userEmail: email })
          .sort({ date: -1 })
          .toArray();
        res.json(userReviews);
      } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch user reviews" });
      }
    });

    // PATCH /reviews/:id → update a review
    app.patch("/reviews/:id", async (req, res) => {
      try {
        const reviewId = req.params.id;
        const updateData = req.body; // e.g., { comment: "...", rating: 4 }

        if (!reviewId) {
          return res.status(400).json({ message: "Review ID is required" });
        }

        const result = await reviewCollection.updateOne(
          { _id: new ObjectId(reviewId) },
          { $set: updateData }
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

    // _______________________Favorites__________________
    // Fetch all favorites for a user
    app.get("/favorites/:email", verifyJWT, async (req, res) => {
      try {
        const email = req.params.email;
        const favorites = await favoritesCollection
          .find({ userEmail: email })
          .toArray();
        res.status(200).json(favorites);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Failed to fetch favorites" });
      }
    });

    // DELETE a favorite meal
    app.delete("/favorites/:id", verifyJWT, async (req, res) => {
      try {
        const id = req.params.id;
        if (!id)
          return res.status(400).json({ message: "Favorite ID required" });

        const result = await favoritesCollection.deleteOne({
          _id: new ObjectId(id),
        });

        if (result.deletedCount === 0)
          return res.status(404).json({ message: "Favorite not found" });

        res.status(200).json({ success: true, message: "Favorite removed" });
      } catch (err) {
        console.error(err);
        res
          .status(500)
          .json({ success: false, message: "Failed to remove favorite" });
      }
    });

    // POST /favorites
    app.post("/favorites", async (req, res) => {
      try {
        const {
          userEmail,
          mealId,
          mealName,
          chefId,
          chefName,
          price,
          foodImage,
          createdAt,
        } = req.body;

        // Validate required fields
        if (!userEmail || !mealId) {
          return res
            .status(400)
            .json({ message: "userEmail and mealId are required" });
        }

        // Check if the meal is already favorited by the user
        const exists = await favoritesCollection.findOne({ userEmail, mealId });
        if (exists) {
          return res.status(400).json({ message: "Meal already in favorites" });
        }

        // Insert favorite
        const result = await favoritesCollection.insertOne({
          userEmail,
          mealId,
          mealName,
          chefId,
          chefName,
          price,
          foodImage,
          createdAt: createdAt || new Date(),
        });

        res.status(201).json({ success: true, insertedId: result.insertedId });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Failed to add favorite" });
      }
    });

    // Only admin can fetch all requests
    app.get(
      "/admin/requests",
      verifyJWT,
      verifyRole("admin"),
      async (req, res) => {
        try {
          const requests = await requestsCollection.find().toArray();
          res.status(200).json(requests);
        } catch (err) {
          console.error("Failed to fetch requests:", err);
          res.status(500).json({ message: "Failed to fetch requests" });
        }
      }
    );

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

run().then(() => {
  app.listen(port, () => console.log(`Server running on port ${port}`));
}).catch(err => console.error(err));

