import "dotenv/config";
import express from "express";
import authRoutes from "./routes/authRoutes.js";
import { connectDB } from "./lib/db.js";

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.use("/api/auth", authRoutes);

app.listen(PORT, () => {
  console.log(`Serve is running on port ${PORT}`);
  connectDB();
});
