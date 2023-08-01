const jwt = require("jsonwebtoken");
const User = require("../model/userSchema");

const Authenticate = async (req, res, next) => {
    try {

        const token = req.cookies.jwtoken;
        if (!token) {
            return res.status(401).send("Unauthorized: No token provided");
          }
        const verifyToken = jwt.verify(token, process.env.SECRET_KEY);

        const rootUser = await User.findOne({ _id: verifyToken._id, "tokens.token": token });

        // if (!rootUser) { throw new Error('User not Found') }
        if (!rootUser) {
            return res.status(401).send("Unauthorized: User not found");
          }
        req.token = token;
        req.rootUser = rootUser;
        req.userID = rootUser._id;

        next();
        
    } catch (err) {
        if (err.name === "JsonWebTokenError") {
          return res.status(401).send("Unauthorized: Invalid token");
        } else if (err.name === "TokenExpiredError") {
          return res.status(401).send("Unauthorized: Token has expired");
        }
        console.error("Authentication error:", err);
        res.status(500).send("Internal Server Error");
      }
    // catch (err) {
    //     res.status(401).send('Unauthorized:No token provided');
    //     console.log(err);
    // }
}

module.exports = Authenticate;
