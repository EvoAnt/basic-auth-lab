var express = require("express");
var router = express.Router();

const { isLoggedIn } = require("../middleware/route-guard");


router.get("/userProfile", isLoggedIn, (req, res, next) => {
  
  res.render("users/user-profile.hbs", { user: req.session.user });
});

module.exports = router;
