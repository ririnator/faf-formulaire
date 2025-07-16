// backend/config/cloudinary.js
const { v2: cloudinary } = require('cloudinary');

cloudinary.config({
  cloud_name:    process.env.CLOUDINARY_CLOUD_NAME,   // ex: "mon-cloud"
  api_key:       process.env.CLOUDINARY_API_KEY,     // ta clé API
  api_secret:    process.env.CLOUDINARY_API_SECRET,  // ton secret API
  secure:        true
});

module.exports = cloudinary;