// backend/config/cloudinary.js
const { v2: cloudinary } = require('cloudinary');

cloudinary.config({
  cloud_name:    process.env.CLOUDINARY_CLOUD,   // ex: "mon-cloud"
  api_key:       process.env.CLOUDINARY_KEY,     // ta clé API
  api_secret:    process.env.CLOUDINARY_SECRET,  // ton secret API
  secure:        true
});

console.log("Cloudinary config:", {
    cloud_name: cloudinary.config().cloud_name,
    api_key:    cloudinary.config().api_key
  });

module.exports = cloudinary;