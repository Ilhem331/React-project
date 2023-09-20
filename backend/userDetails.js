const mongoose = require("mongoose");
const userSchema = new mongoose.Schema({
username: { type: String },
email: { type: String, required: true, unique: true },
password: { type: String, required: true, minlength: 5 },
pic: {
    type: String,
    default:
      "https://icon-library.com/images/anonymous-avatar-icon/anonymous-avatar-icon-25.jpg",
  },
bio: { type: String },
coverpic: {
    type: String,
    default:
      "https://res.cloudinary.com/dh0yeirqu/image/upload/v1679490285/izvzaudiqlw3ysxkb4e7.jpg",
  },

});
module.exports = User = mongoose.model("users", userSchema);