const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ResponseSchema = new Schema({
  name: { type: String, required: true },
  responses: [
    {
      question: String,
      answer: String
    }
  ],
  month: { type: String, required: true },        // ex. "2025-08"
  isAdmin: { type: Boolean, default: false },     // flag pour la réponse admin
  token: { type: String, unique: true, sparse: true }, // lien privé (null pour admin)
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Response', ResponseSchema);