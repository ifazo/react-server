import { MongoClient, ObjectId, ServerApiVersion } from "mongodb";
import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import Stripe from "stripe";

const app = express();
app.use(express.json());
app.use(cors());
dotenv.config();

const uri = process.env.MONGODB_URI;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// This is your test secret API key.
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY)

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).send({ error: true, message: "Unauthorized access" });
  }
  const secret = process.env.JWT_SECRET_TOKEN;
  try {
    jwt.verify(token, secret);
    next();
  } catch (error) {
    return res.status(401).send({ error: true, message: "Invalid token" });
  }
};

const sendResponse = (res, status, data) => {
  res.status(status).send(data);
};

const errorHandler = (err, req, res, next) => {
  console.error(err.message);
  sendResponse(res, 500, { error: true, message: "Internal Server Error" });
};

async function run() {
  const db = client.db(process.env.MONGODB_DB);
  const userCollection = db.collection("users");
  const productCollection = db.collection("products");
  const categoryCollection = db.collection("categories");
  const reviewCollection = db.collection("reviews");
  const orderCollection = db.collection("orders");

  app.get("/", (_req, res) => {
    sendResponse(res, 200, { message: "React server is running!" });
  });

  app.post("/api/payment", async (req, res) => {
    const data = req.body;
  
    const paymentIntent = await stripe.paymentIntents.create({
      amount: data.amount,
      currency: "usd",
      automatic_payment_methods: {
        enabled: true,
      },
    });

    sendResponse(res, 200, { clientSecret: paymentIntent.client_secret });
  
    // res.send({
    //   clientSecret: paymentIntent.client_secret,
    //   // [DEV]: For demo purposes only, you should avoid exposing the PaymentIntent ID in the client-side code.
    //   // dpmCheckerLink: `https://dashboard.stripe.com/settings/payment_methods/review?transaction_id=${paymentIntent.id}`,
    // });
  });

  app.post("/api/token", async (req, res) => {
    const data = req.body;
    const user = await userCollection.findOne({ email: data.email });
    if (!user) {
      return sendResponse(res, 400, { error: true, message: "User does not exist" });
    }
    const payload = {
      id: user._id,
      name: user.name,
      email: user.email,
    };
    const JWToken = process.env.JWT_SECRET_TOKEN;
    const token = jwt.sign(payload, JWToken);
    sendResponse(res, 200, { token });
  });

  app.post("/api/auth/signup", async (req, res) => {
    try {
      const { name, email, password } = req.body;
      const existingUser = await userCollection.findOne({ email });
      if (existingUser) {
        return sendResponse(res, 400, { error: true, message: "User already exists" });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = { name, email, password: hashedPassword };
      const createUser = await userCollection.insertOne(user);
      if (!createUser) {
        return sendResponse(res, 400, { error: true, message: "User not created" });
      }
      const payload = {
        name: user.name,
        email: user.email,
      };
      const JWTtoken = process.env.JWT_SECRET_TOKEN;
      const token = jwt.sign(payload, JWTtoken);
      sendResponse(res, 201, { token });
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/auth/signin", async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = await userCollection.findOne({ email });
      if (!user) {
        return sendResponse(res, 400, { error: true, message: "User does not exist" });
      }
      const isPasswordCorrect = await bcrypt.compare(password, user?.password);
      if (!isPasswordCorrect) {
        return sendResponse(res, 400, { error: true, message: "Password is incorrect" });
      }
      const payload = {
        name: user.name,
        email: user.email,
      };
      const JWTtoken = process.env.JWT_SECRET_TOKEN;
      const token = jwt.sign(payload, JWTtoken);
      sendResponse(res, 200, { token });
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/users", authMiddleware, async (_req, res) => {
    try {
      const users = await userCollection.find().toArray();
      sendResponse(res, 200, users);
    } catch (error) {
      next(error);
    }
  });

  app.patch("/api/users/:id", authMiddleware, async (req, res) => {
    try {
      const { id } = req.params;
      const user = req.body;
      const result = await userCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: user }
      );
      sendResponse(res, 200, result);
    } catch (error) {
      next(error);
    }
  });

  app.delete("/api/users/:id", authMiddleware, async (req, res) => {
    try {
      const { id } = req.params;
      const result = await userCollection.deleteOne({
        _id: new ObjectId(id),
      });
      sendResponse(res, 200, result);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/products", async (req, res) => {
    try {
      const { search, category, price, rating, skip, limit, sort } = req.query;

      let query = {};
      if (search) {
        query.$or = [
          { title: { $regex: search, $options: "i" } },
          { description: { $regex: search, $options: "i" } },
        ];
      } else if (category) {
        query.category = category;
      } else if (price) {
        query.price = { $lte: parseInt(price) };
      } else if (rating) {
        query.rating = { $gte: parseInt(rating) };
      }

      let cursor = productCollection.find(query);

      if (skip) cursor = cursor.skip(parseInt(skip));
      if (limit) cursor = cursor.limit(parseInt(limit));
      if (sort) cursor = cursor.sort({ title: sort === "asc" ? 1 : -1 });

      const products = await cursor.toArray();
      sendResponse(res, 200, products);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/products/random", async (req, res) => {
    try {
      const products = await productCollection.aggregate([
        { $sample: { size: 10 } },
      ]).toArray();
      sendResponse(res, 200, products);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/products/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const product = await productCollection.findOne({ _id: new ObjectId(id) });
      sendResponse(res, 200, product);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/products/:user", async (req, res) => {
    try {
      const { user } = req.params;
      const products = await productCollection.find({ user }).toArray();
      sendResponse(res, 200, products);
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/products", authMiddleware, async (req, res) => {
    try {
      const token = req.headers.authorization?.split(" ")[1];
      const JWTtoken = process.env.JWT_SECRET_TOKEN;
      const decodedToken = jwt.verify(token, JWTtoken);
      const { email } = decodedToken;
      const product = req.body;
      product.user = email;
      product.createdAt = new Date();
      const result = await productCollection.insertOne(product);
      sendResponse(res, 201, result);
    } catch (error) {
      next(error);
    }
  });

  app.patch("/api/products/:id", authMiddleware, async (req, res) => {
    try {
      const product = req.body;
      const { id } = req.params;
      const token = req.headers.authorization?.split(" ")[1];
      const JWTtoken = process.env.JWT_SECRET_TOKEN;
      const decodedToken = jwt.verify(token, JWTtoken);
      const { email } = decodedToken;
      const findproduct = await productCollection.findOne({
        _id: new ObjectId(id),
      });
      if (findproduct?.email !== email) {
        return sendResponse(res, 403, { error: true, message: "Unauthorized access" });
      }
      const result = await productCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: product }
      );
      sendResponse(res, 200, result);
    } catch (error) {
      next(error);
    }
  });

  app.delete("/api/products/:id", authMiddleware, async (req, res) => {
    try {
      const { id } = req.params;
      const token = req.headers.authorization?.split(" ")[1];
      const JWTtoken = process.env.JWT_SECRET_TOKEN;
      const decodedToken = jwt.verify(token, JWTtoken);
      const { email } = decodedToken;
      const product = await productCollection.findOne({
        _id: new ObjectId(id),
      });
      if (product?.user !== email) {
        return sendResponse(res, 403, { error: true, message: "Unauthorized access" });
      }
      const result = await productCollection.deleteOne({
        _id: new ObjectId(id),
      });
      sendResponse(res, 200, result);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/categories", async (req, res) => {
    try {
      const categories = await categoryCollection.find().toArray();
      sendResponse(res, 200, categories);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/categories/:category", async (req, res) => {
    try {
      const { category } = req.params;
      const products = await productCollection.find({ category }).toArray();
      sendResponse(res, 200, products);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/reviews/:productId", async (req, res) => {
    try {
      const { productId } = req.params;
      const result = await reviewCollection.find({ productId }).toArray();
      sendResponse(res, 200, result);
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/reviews/:productId", authMiddleware, async (req, res) => {
    try {
      const { productId } = req.params;
      const token = req.headers.authorization?.split(" ")[1];
      const JWTtoken = process.env.JWT_SECRET_TOKEN;
      const decodedToken = jwt.verify(token, JWTtoken);
      const { name, email } = decodedToken;
      const data = req.body;
      data.productId = productId;
      data.name = name;
      data.email = email;
      data.createdAt = new Date();
      const result = await reviewCollection.insertOne(data);
      sendResponse(res, 201, result);
    } catch (error) {
      next(error);
    }
  });

  app.get("/api/orders", authMiddleware, async (req, res) => {
    try {
      const { user } = req.query;
      const orders = await orderCollection.find({ user }).toArray();
      sendResponse(res, 200, orders);
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/orders", authMiddleware, async (req, res) => {
    try {
      const data = req.body;
      const token = req.headers.authorization?.split(" ")[1];
      const JWTtoken = process.env.JWT_SECRET_TOKEN;
      const decodedToken = jwt.verify(token, JWTtoken);
      const { email } = decodedToken;
      const user = await userCollection.findOne({ email });
      if (!user) {
        return sendResponse(res, 404, { error: true, message: "User not found" });
      }
      data.user = email;
      data.createdAt = new Date();
      const result = await orderCollection.insertOne(data);
      sendResponse(res, 201, result);
    } catch (error) {
      next(error);
    }
  });

  app.use(errorHandler);
}

run().catch(console.dir);

const port = process.env.PORT;

app.listen(port, () => {
  console.log(`React server listening on port ${port}`);
});