import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

// Middleware to check if the user is authenticated
export const protectRoute = async (req, res, next) => {
  try {
    const accessToken = req.cookies.accessToken;
    if (!accessToken) {
      return res
        .status(401)
        .json({ message: "Unauthorized - No access token provided" });
    }

    // Verify the access token
    try {
      const decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
      const user = await User.findById(decoded.userId).select("-password");

      // Check if user exists in the database
      if (!user) {
        return res.status(401).json({ message: "User not found" });
      }
      req.user = user;
      next();
    } catch (error) {
      // Handle token verification errors
      if (error.name === "TokenExpiredError") {
        return res.status(401).json({ message: "Access token expired" });
      }
      throw error;
    }
    // If the access token is not valid, return an error
  } catch (error) {
    console.log("Error in protect route middleware", error);
    res.status(500).json({ message: "Unauthorized - Invalid access token" });
  }
};

// Middleware to check if the user is an admin
export const adminRoute = async (req, res, next) => {
  if (req.user.role === "admin") {
    next();
  } else {
    return res.status(403).json({ message: "Access Denied - Admin only" });
  }
};
