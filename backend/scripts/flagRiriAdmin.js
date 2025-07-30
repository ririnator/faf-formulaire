// backend/scripts/flagRiriAdmin.js
require('dotenv').config();
const mongoose  = require('mongoose');
const Response  = require('../models/Response');

(async () => {
  await mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
  const month = new Date().toISOString().slice(0,7); // ex. "2025-07"

  const result = await Response.updateMany(
    { 
      name: { $regex: /^riri$/i },
      month 
    },
    { $set: { isAdmin: true, token: null } }
  );

  console.log(`Matched: ${result.matchedCount}, Modified: ${result.modifiedCount}`);
  process.exit(0);
})();
