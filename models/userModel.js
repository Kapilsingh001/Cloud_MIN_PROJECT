/**
 * models/userModel.js
 * ────────────────────────────────────────────────
 * Mongoose schema for user accounts.
 * Handles:
 *  • Username and email uniqueness
 *  • bcrypt password hashing (salt rounds: 12)
 *  • Password comparison method
 *  • Account suspension flag
 *  • Timestamps (createdAt, updatedAt)
 */

'use strict';

const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');

const userSchema = new mongoose.Schema(
  {
    // ── Username ───────────────────────────────────────────
    username: {
      type:      String,
      required:  [true, 'Username is required'],
      unique:    true,
      trim:      true,
      minlength: [3,  'Username must be at least 3 characters'],
      maxlength: [20, 'Username cannot exceed 20 characters'],
      // Must start with a letter; only letters, numbers, underscore, dot
      match: [/^[a-zA-Z][a-zA-Z0-9_.]*$/, 'Username can only contain letters, numbers, underscores, and dots, and must start with a letter'],
    },

    // ── Email ──────────────────────────────────────────────
    email: {
      type:      String,
      required:  [true, 'Email address is required'],
      unique:    true,
      trim:      true,
      lowercase: true,
      maxlength: [254, 'Email address is too long'],
      match: [
        /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/,
        'Please provide a valid email address',
      ],
    },

    // ── Password (stored as bcrypt hash) ──────────────────
    password: {
      type:      String,
      required:  [true, 'Password is required'],
      minlength: [8, 'Password must be at least 8 characters'],
    },

    // ── Account status ─────────────────────────────────────
    suspended: {
      type:    Boolean,
      default: false,
    },

    // ── Last login timestamp ───────────────────────────────
    lastLogin: {
      type: Date,
    },
  },
  { timestamps: true } // adds createdAt and updatedAt
);

// ── Hash password before saving ─────────────────────────────
// Only runs when the password field is modified (new user or password change)
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  try {
    const salt    = await bcrypt.genSalt(12); // 12 salt rounds = strong security
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

// ── Instance method: compare plain password against hash ────
userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// ── Instance method: update last login time ─────────────────
userSchema.methods.updateLastLogin = function () {
  this.lastLogin = new Date();
  return this.save({ validateBeforeSave: false });
};

// ── Prevent password from being serialized in JSON ──────────
userSchema.set('toJSON', {
  transform(doc, ret) {
    delete ret.password;
    return ret;
  },
});

module.exports = mongoose.model('User', userSchema);
