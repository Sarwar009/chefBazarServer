require ('dotenv').config ();
const express = require ('express');
const cors = require ('cors');
const {MongoClient, ServerApiVersion, ObjectId} = require ('mongodb');
const admin = require ('firebase-admin');
const jwt = require ('jsonwebtoken');
const port = process.env.PORT || 3000;

const secret = process.env.JWT_SECRET;

const decoded = Buffer.from (process.env.FB_SERVICE_KEY, 'base64').toString (
  'utf-8'
);
const serviceAccount = JSON.parse (decoded);
admin.initializeApp ({
  credential: admin.credential.cert (serviceAccount),
});

const app = express ();
// middleware
app.use (cors ());
app.use (express.json ());

const verifyJWT = (req, res, next) => {
  const authorizationHeader = req.headers.authorization;
  if (!authorizationHeader) {
    return res.status (401).send ({error: true, message: 'token unavailable'});
  }
  const token = authorizationHeader.split (' ')[1];
  jwt.verify (token, secret, (err, decoded) => {
    if (err) {
      console.error ('JWT failed', err);
      return res.status (403).send ({error: true, message: 'Forbidden'});
    }

    req.decoded = decoded;
    req.email = decoded.email;
    req.role = decoded.role || 'user';

    next ();
  });
};
// Role check middleware
const verifyRole = requiredRoles => (req, res, next) => {
  if (!req.role) {
    return res.status (403).send ({message: 'Access Denied: Role not found'});
  }

  const rolesArray = Array.isArray (requiredRoles)
    ? requiredRoles
    : [requiredRoles];

  if (!rolesArray.includes (req.role)) {
    return res
      .status (403)
      .send ({message: 'Access Denied: Insufficient role'});
  }

  next ();
};

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient (process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let usersCollection;

async function run () {
  try {
    const db = client.db ('mealDB');
    // user Collection
    usersCollection = db.collection ('user');
    // Meals Collection
    const mealsCollection = db.collection ('meals');
    // revierws Collection
    const reviewCollection = db.collection ('reviews');
    // favorites Collection
    const favoritesCollection = db.collection ('favorites');
    // order Collection
    const orderCollection = db.collection ('order_collection');
    // request collection
    const requestCollection = db.collection('request')

    // user setup
    app.post ('/register', async (req, res) => {
      const {email, displayName} = req.body;
      const existing = await usersCollection.findOne ({email});
      if (existing) return res.send ({message: 'Already registered'});

      const result = await usersCollection.insertOne ({
        email,
        displayName,
        role: 'user', // default role
      });
      res.send ({result});
    });

    // Issue JWT after Firebase login
    app.post ('/jwt', async (req, res) => {
      const {email, displayName} = req.body;
      let user = await usersCollection.findOne ({email});

      if (!user) {
        // Auto-register new Google user
        const result = await usersCollection.insertOne ({
          email,
          displayName: displayName || email.split ('@')[0],
          role: 'user',
        });
        user = {_id: result.insertedId, email, displayName, role: 'user'};
      }

      const token = jwt.sign (
        {email, role: user.role},
        process.env.JWT_SECRET,
        {
          expiresIn: '30d',
        }
      );

      res.send ({token, role: user.role});
    });

    // Get all users (Admin only)
    app.get ('/users', verifyJWT, verifyRole ('admin'), async (req, res) => {
      const users = await usersCollection.find ().toArray ();
      res.send (users);
    });

    // Promote / Demote user (Admin only)
    app.patch (
      '/users/:id/role',
      verifyJWT,
      verifyRole ('admin'),
      async (req, res) => {
        try {
          const {role} = req.body; // 'user', 'seller', 'admin'
          const userId = req.params.id;

          // 1️⃣ Find user in MongoDB
          const user = await usersCollection.findOne ({
            _id: new ObjectId (userId),
          });
          if (!user) return res.status (404).send ({message: 'User not found'});

          // 2️⃣ Update role in MongoDB
          await usersCollection.updateOne (
            {_id: new ObjectId (userId)},
            {$set: {role}}
          );

          // 3️⃣ Update Firebase custom claim
          // Firebase uses email to set claims
          await admin.auth ().setCustomUserClaims (user.email, {role});

          res.send ({message: `User role updated to ${role}`});
        } catch (err) {
          console.error (err);
          res
            .status (500)
            .send ({message: 'Failed to update role', error: err.message});
        }
      }
    );

    // request qpi
    // Submit request
app.post('/requests', verifyJWT, async (req, res) => {
  const request = req.body; // {userName, userEmail, requestType, requestStatus, requestTime}
  try {
    const result = await requestsCollection.insertOne(request);
    res.send({ success: true, insertedId: result.insertedId });
  } catch (err) {
    console.error(err);
    res.status(500).send({ success: false, error: err.message });
  }
});

// Get all requests (admin)
app.get('/requests', verifyJWT, verifyRole('admin'), async (req, res) => {
  const requests = await requestsCollection.find().toArray();
  res.send(requests);
});

// Approve/Reject request
app.patch('/requests/:id', verifyJWT, verifyRole('admin'), async (req, res) => {
  const id = req.params.id;
  const { action } = req.body; // "approved" or "rejected"
  try {
    const request = await requestsCollection.findOne({ _id: new ObjectId(id) });
    if (!request) return res.status(404).send({ message: 'Request not found' });

    await requestsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { requestStatus: action } }
    );

    // If approved, update user role and generate chefId
    if (action === 'approved') {
      const roleUpdate = request.requestType === 'chef' ? 'chef' : 'admin';
      const chefId = roleUpdate === 'chef' ? `chef-${Math.floor(1000 + Math.random() * 9000)}` : null;

      await usersCollection.updateOne(
        { email: request.userEmail },
        { $set: { role: roleUpdate, chefId: chefId } }
      );
    }

    res.send({ success: true, action });
  } catch (err) {
    console.error(err);
    res.status(500).send({ success: false, error: err.message });
  }
});



    // Example protected route for sellers
    app.get ('/seller/data', verifyJWT, verifyRole ('seller'), (req, res) => {
      res.send ({secretData: 'Only seller can see this'});
    });

    // Example protected route for users
    app.get ('/user/data', verifyJWT, verifyRole ('user'), (req, res) => {
      res.send ({secretData: 'Only normal user can see this'});
    });

    // GET /chef/stats/:uid
app.get("/dashboard/chef/stats/:uid", async (req, res) => {
  const uid = req.params.uid;

  const meals = await mealsCollection.find({ chefId: uid }).toArray();
  const orders = await orderCollection.find({ chefId: uid }).toArray();

  const totalMeals = meals.length;
  const totalOrders = orders.length;

  // Avg rating
  const allRatings = meals.flatMap(m => m.reviews?.map(r => r.rating) || []);
  const avgRating =
    allRatings.length > 0
      ? allRatings.reduce((a, b) => a + b, 0) / allRatings.length
      : 0;

  // Total revenue
  const totalRevenue = orders.reduce(
    (sum, order) => sum + order.price * order.quantity,
    0
  );

  res.send({
    totalMeals,
    totalOrders,
    avgRating,
    totalRevenue,
  });
});


    // meals APIs

    app.post ('/meals', async (req, res) => {
      const meal = req.body;
      const result = await mealsCollection.insertOne (meal);
      res.status(200).json({
        massage: 'Successful',
        data: result
      });
    });

    app.get ('/meals', async (req, res) => {
      const cursor = mealsCollection.find ();
      const meals = await cursor.toArray ();
      res.send (meals);
    });

    app.get('/meals/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const meal = await mealsCollection.findOne({_id: new ObjectId(id)});
    res.send(meal);
  } catch (err) {
    console.log("Error:", err.message);
    res.status(500).send({ error: err.message });
  }
});


    // Update meal
app.put('/meals/:id', verifyJWT, async (req, res) => {
  const id = req.params.id;
  const updatedMeal = req.body;
  try {
    const result = await mealsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updatedMeal }
    );
    res.send({ success: true, modifiedCount: result.modifiedCount });
  } catch (err) {
    console.error(err);
    res.status(500).send({ success: false, error: err.message });
  }
});

// Delete meal
app.delete('/meals/:id', verifyJWT, async (req, res) => {
  const id = req.params.id;
  try {
    const result = await mealsCollection.deleteOne({ _id: new ObjectId(id) });
    res.send({ success: true, deletedCount: result.deletedCount });
  } catch (err) {
    console.error(err);
    res.status(500).send({ success: false, error: err.message });
  }
});

// Get meals by chef
app.get('/meals/chef/:chefId', async (req, res) => {
  const chefId = req.params.chefId;
  const meals = await mealsCollection.find({ chefId }).toArray();
  res.send(meals);
});


    // reviews APIs
    // POST new review
    app.post('/reviews', async (req, res) => {
  try {
    const review = req.body;
    // Ensure required fields exist
    const safeReview = {
      foodId: review.foodId,
      rating: review.rating || 0,
      comment: review.comment || '',
      reviewerName: review.reviewerName || 'Anonymous',
      reviewerImage: review.reviewerImage || '',
      date: new Date(),
    };
    const result = await reviewCollection.insertOne(safeReview);
    res.status(200).json({ ...safeReview, insertedId: result.insertedId });
  } catch (err) {
    console.error('Error adding review:', err);
    res.status(500).json({ error: 'Failed to add review' });
  }
});

    // get all review
    app.get ('/reviews', verifyJWT, verifyRole ('admin'), async (req, res) => {
      try {
        const userId = req._id;
        const reviews = await reviewCollection
          .find ({user_Id: userId})
          .toArray ();
        res.status (200).json ({
          massage: 'Review Data successfully find',
          data: reviews
        });
      } catch (error) {
        console.error ('Database error in /reviews:', error);
        res.status (500).json ({
          message: 'Failed to fetch reviews due to server error',
        });
      }
    });
    // GET reviews by mealId
    app.get ('/reviews/:mealId', async (req, res) => {
      try {
        const mealId = req.params.mealId;
        const reviews = await reviewCollection
          .find ({foodId: mealId})
          .sort ({date: -1})
          .toArray ();
        res.json (reviews);
      } catch (err) {
        console.error (err);
        res.status (500).json ({error: 'Failed to fetch reviews'});
      }
    });

    // DELETE review by reviewId
    app.delete ('/reviews/:reviewId', async (req, res) => {
      try {
        const reviewId = req.params.reviewId;
        const result = await reviewCollection.deleteOne ({
          _id: new ObjectId (reviewId),
        });
        if (result.deletedCount === 1) {
          res.status (200).json ({message: 'Review deleted successfully'});
        }
      } catch (err) {
        console.error (err);
        res.status (500).json ({error: 'Failed to delete review'});
      }
    });

    // post favorite meal
    app.post ('/favorites', async (req, res) => {
      try {
        const favorite = req.body;

        const existing = await favoritesCollection.findOne ({
          userEmail: favorite.userEmail,
          mealId: favorite.mealId,
        });

        if (existing) {
          return res.send ({alreadyExists: true});
        }

        // insert favorite (foodImage সহ)
        const result = await favoritesCollection.insertOne (favorite);

        res.send ({
          alreadyExists: false,
          ...favorite, // <-- এখানে foodImage থাকবে
          _id: result.insertedId.toString (),
        });
      } catch (err) {
        console.error (err);
        res.status (500).json ({error: 'Failed to add favorite'});
      }
    });

    // GET /favorites/:userEmail
    app.get ('/favorites/:userEmail', async (req, res) => {
      try {
        const userEmail = req.params.userEmail;
        const favorites = await favoritesCollection
          .find ({userEmail})
          .toArray ();
        res.status (200).json (favorites);
      } catch (err) {
        console.error (err);
        res.status (500).json ({error: 'Failed to fetch favorites'});
      }
    });

    // DELETE /favorites/:id
    app.delete ('/favorites/:id', async (req, res) => {
      try {
        const result = await favoritesCollection.deleteOne ({
          _id: new ObjectId (req.params.id),
        });

        if (result.deletedCount === 1) {
          res.status (200).json ({message: 'Favorite deleted successfully'});
        } else {
          res.status (404).json ({message: 'Favorite not found'});
        }
      } catch (err) {
        console.error (err);
        res.status (500).json ({error: 'Failed to delete favorite'});
      }
    });

    // Order Api

    app.post ('/orders', async (req, res) => {
      try {
        const result = await orderCollection.insertOne (req.body);

        res.send ({success: true, insertedId: result.insertedId});
      } catch (error) {
        console.error (error);
        res.status (500).send ({success: false, error: 'Something went wrong'});
      }
    });

    app.get ('/orders', async (req, res) => {
      try {
        const orders = await orderCollection.find ().toArray ();
        res.status (200).json (orders);
      } catch (err) {
        console.error ('Failed to fetch orders:', err);
        res
          .status (500)
          .json ({message: 'Failed to fetch orders', error: err.message});
      }
    });

    // Update order status
app.patch('/orders/:id/status', verifyJWT, async (req, res) => {
  const id = req.params.id;
  const { status } = req.body; // "pending", "accepted", "delivered", "cancelled"
  try {
    const result = await orderCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { orderStatus: status } }
    );
    res.send({ success: true, modifiedCount: result.modifiedCount });
  } catch (err) {
    console.error(err);
    res.status(500).send({ success: false, error: err.message });
  }
});


    app.get('/chef/orders/:id', async (req, res) => {
  const id = req.params.id;

  const orders = await orderCollection.find({ chefId: id }).toArray();
  res.json(orders);
});

app.get("/orders/user/:email", async (req, res) => {
  const email = req.params.email;
  const orders = await ordersCollection
    .find({ userEmail: email })
    .sort({ orderTime: -1 })
    .toArray();

  res.send(orders);
});

app.patch("/orders/cancel/:id", async (req, res) => {
  const id = req.params.id;

  const result = await ordersCollection.updateOne(
    { _id: new ObjectId(id) },
    { $set: { orderStatus: "canceled" } }
  );

  res.send(result);
});

    // Dashboard-----------------------------------------------------
    // For admin

    app.put ('/users/:id/block', async (req, res) => {
      const userId = req.params.id;

      try {
        const result = await req.db.collection ('users').updateOne (
          {_id: new ObjectId (userId)}
          // { $set: { isBlocked: true } }
        );
        if (result.modifiedCount === 1) {
          res.json ({message: `User ${userId} blocked successfully.`});
        } else {
          res.status (404).json ({message: 'User not found.'});
        }
      } catch (error) {
        res.status (500).json ({message: 'Error blocking user.', error});
      }
    });

    app.get ('/stats', async (req, res) => {
      try {
        const totalUsers = await req.db.collection ('users').countDocuments ();
        const totalOrders = await req.db
          .collection ('orders')
          .countDocuments ();
        const totalChefs = await req.db
          .collection ('users')
          .countDocuments ({role: 'chef'});

        res.json ({
          totalUsers,
          totalOrders,
          totalChefs,
        });
      } catch (error) {
        res.status (500).json ({message: 'Failed to fetch statistics', error});
      }
    });

    // User Profile Update -----------------------------

    app.put ('/update-user', async (req, res) => {
      const {email, name, photo} = req.body;

      await usersCollection.updateOne (
        {email},
        {$set: {displayName: name, photoURL: photo}}
      );

      res.send ({success: true});
    });

    // statistcs
    app.get('/platform/stats', verifyJWT, verifyRole('admin'), async (req, res) => {
  try {
    const totalUsers = await usersCollection.countDocuments();
    const totalChefs = await usersCollection.countDocuments({ role: 'chef' });
    const totalOrders = await orderCollection.countDocuments();
    const ordersDelivered = await orderCollection.countDocuments({ orderStatus: 'delivered' });
    const ordersPending = await orderCollection.countDocuments({ orderStatus: 'pending' });

    const totalRevenueAgg = await orderCollection.aggregate([
      { $match: { paymentStatus: 'paid' } },
      { $group: { _id: null, totalRevenue: { $sum: { $multiply: ['$price', '$quantity'] } } } }
    ]).toArray();

    const totalRevenue = totalRevenueAgg[0]?.totalRevenue || 0;

    res.send({ totalUsers, totalChefs, totalOrders, ordersDelivered, ordersPending, totalRevenue });
  } catch (err) {
    console.error(err);
    res.status(500).send({ error: 'Failed to fetch platform stats' });
  }
});























    // Send a ping to confirm a successful connection
    await client.db ('admin').command ({ping: 1});
    console.log (
      'Pinged your deployment. You successfully connected to MongoDB!'
    );
  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run ().catch (console.dir);

app.get ('/', (req, res) => {
  res.send ('Hello from Server..');
});

app.listen (port, () => {
  console.log (`Server is running on port ${port}`);
});
