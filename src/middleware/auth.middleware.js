import jwt from "jsonwebtoken";
import User from "../models/User.js";

const protectRoute = async (req, res, next) => {
  try {
    // get token
    const token = req.header("Authorization").replace("Bearer ", "");
    if (!token)
      return res
        .status(401)
        .json({ message: "No authentication token, access denied" });
    // verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    // find user from token
    const user = await User.findById(decoded.userId).select("_password");

    if (!user) return res.status(401).json({ message: "Token is not valid" });
    req.user = user;
    next();
  } catch (error) {
    console.log("Authentication error", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
};

export default protectRoute;
