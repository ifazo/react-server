import { MongoClient, ObjectId, ServerApiVersion } from "mongodb";
import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

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

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.send({ error: true, message: "unauthorized access" });
  }
  const secret = process.env.JWT_SECRET_TOKEN;
  jwt.verify(token, secret);
  next();
};

async function run() {
  const db = client.db("react_db");
  const userCollection = db.collection("users");
  const productCollection = db.collection("products");
  const categoryCollection = db.collection("categories");
  const reviewCollection = db.collection("reviews");
  const orderCollection = db.collection("orders");

  app.get("/", (_req, res) => {
    res.send("Express Mongo server is running!");
  });

  app.post("/api/token", async (req, res) => {
    const data = req.body;
    const user = await userCollection.findOne({ email: data.email });
    if (!user) {
      return res.status(400).send("User does not exist");
    }
    const payload = {
      id: user._id,
      name: user.name,
      email: user.email,
    };
    const JWToken = process.env.JWT_SECRET_TOKEN;
    const token = jwt.sign(payload, JWToken);
    return res.send({ token });
  });

  app.post("/api/auth/signup", async (req, res) => {
    try {
      const data = req.body;
      const { name, email, password } = data;
      const existingUser = await userCollection.findOne({ email });
      if (existingUser) {
        return res.status(400).send("User already exists");
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = { name, email, password: hashedPassword };
      const createUser = await userCollection.insertOne(user);
      if (!createUser) {
        return res.status(400).send("User not created");
      }
      const payload = {
        name: user.name,
        email: user.email,
      };
      const JWTtoken = process.env.JWT_SECRET_TOKEN;
      const token = jwt.sign(payload, JWTtoken);
      return res.send({ token });
    } catch (error) {
      console.log(error.message);
    }
  });

  app.post("/api/auth/signin", async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = await userCollection.findOne({ email });
      if (!user) {
        return res.status(400).send("User does not exist");
      }
      const isPasswordCorrect = await bcrypt.compare(password, user?.password);
      if (!isPasswordCorrect) {
        return res.status(400).send("Password is incorrect");
      }
      const payload = {
        name: user.name,
        email: user.email,
      };
      const JWTtoken = process.env.JWT_SECRET_TOKEN;
      const token = jwt.sign(payload, JWTtoken);
      return res.send({ token });
    } catch (error) {
      console.log(error.message);
    }
  });

  app.get("/api/users", authMiddleware, async (_req, res) => {
    try {
      const users = await userCollection.find().toArray();
      return res.send(users);
    } catch (error) {
      console.log(error.message);
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
      return res.send(result);
    } catch (error) {
      console.log(error.message);
    }
  });

  app.delete("/api/users/:id", authMiddleware, async (req, res) => {
    try {
      const { id } = req.params;
      const result = await userCollection.deleteOne({
        _id: new ObjectId(id),
      });
      return res.send(result);
    } catch (error) {
      console.log(error.message);
    }
  });

  app.get("/api/products", async (req, res) => {
    try {
      const { search, brand, price, rating, skip, limit } = req.query;

      if (search) {
        const products = await productCollection.find({
          $or: [
            { title: { $regex: search, $options: "i" } },
            { description: { $regex: search, $options: "i" } },
          ],
        }).toArray();
        return res.send(products);
      }
      else if (brand) {
        const products = await productCollection.find({
          brand
        }).toArray();
        return res.send(products);
      }
      else if (price) {
        const products = await productCollection.find({
          price: { $lte: parseInt(price) }
        }).toArray();
        return res.send(products);
      }
      else if (rating) {
        const products = await productCollection.find({
          rating: { $gte: parseInt(rating) }
        }).toArray();
        return res.send(products);
      }
      else if (skip && limit) {
        const products = await productCollection.find().skip(parseInt(skip)).limit(parseInt(limit)).toArray();
        return res.send(products);
      }
      else {
        const products = await productCollection.find().toArray();
        return res.send(products);
      }
    } catch (error) {
      console.log(error.message);
    }
  });

  app.get("/api/products/random", async (req, res) => {
    try {
      const products = productCollection.aggregate([
        { $sample: { size: 10 } },
      ]);
      return res.send(products);
    } catch (error) {
      console.log(error.message);
    }
  });

  app.get("/api/products/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const product = await productCollection.findOne({ _id: new ObjectId(id) });
      return res.send(product);
    } catch (error) {
      console.log(error.message);
    }
  });

  app.get("/api/products/:user", async (req, res) => {
    try {
      const { user } = req.params;
      const products = await productCollection.find({ user }).toArray();
      return res.send(products);
    } catch (error) {
      console.log(error.message);
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
      return res.send(result);
    } catch (error) {
      console.log(error.message);
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
      if (findBook?.email !== email) {
        return res.send("Unauthorized access");
      }
      const result = await productCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: product }
      );
      return res.send(result);
    } catch (error) {
      console.log(error.message);
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
        return res.send("Unauthorized access");
      }
      const result = await productCollection.deleteOne({
        _id: new ObjectId(id),
      });
      return res.send(result);
    } catch (error) {
      console.error(error.message);
    }
  });

  app.get("/api/categories", async (req, res) => {
    const categories = await categoryCollection.find().toArray();
    return res.send(categories);
  });

  app.get("/api/categories/:category", async (req, res) => {
    const { category } = req.params;
    const products = await productCollection.find({
      category
    }).toArray();
    return res.send(products);
  });

  app.get("/api/reviews/:productId", async (req, res) => {
    const { productId } = req.params;
    const result = await reviewCollection.find({ productId }).toArray();
    return res.send(result);
  });

  app.post("/api/reviews/:productId", authMiddleware, async (req, res) => {
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
    const result = await reviewsCollection.insertOne(data);
    return res.send(result);
  });

  app.get("/api/orders", authMiddleware, async (req, res) => {
    const { user } = req.query;
    const orders = await orderCollection.find({ user }).toArray();
    return res.send(orders);
  });

  app.post("/api/orders", authMiddleware, async (req, res) => {
    const data = req.body;
    const token = req.headers.authorization?.split(" ")[1];
    const JWTtoken = process.env.JWT_SECRET_TOKEN;
    const decodedToken = jwt.verify(token, JWTtoken);
    const { email } = decodedToken;
    const user = await userCollection.findOne({ email });
    if (!user) {
      return res.send("User not found");
    }
    data.user = email;
    data.createdAt = new Date();
    const result = await orderCollection.insertOne(data);
    return res.send(result);
  });

}

run().catch(console.dir);

const port = process.env.PORT || 5000;

app.listen(port, () => {
  console.log(`Backend app listening on port ${port}`);
});
