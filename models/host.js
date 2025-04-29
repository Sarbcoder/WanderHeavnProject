const mongoose = require("mongoose");
const passportLocalMongoose = require("passport-local-mongoose");
const { Schema } = mongoose;
const User = require("../models/user");

const hostSchema = new Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        minlength: [5, "Username must be at least 5 characters."]
    },
    email: {
        type: String,
        required: true,
        unique: true,
        match: [/.+\@.+\..+/, "Invalid email format"]
    },
    phone: {
        type: String,
        required: true,
        unique: true,
        minlength: [10, "Phone number must be at least 10 digits."]
    },
    role: {
        type: String,
        default: "host"
    },
    userId: {
        type: Schema.Types.ObjectId,
        ref: "User",
        required: false
    },
    properties: [
        {
            type: Schema.Types.ObjectId,
            ref: "Listing"
        }
    ],
    earnings: {
        totalEarnings: {
            type: Number,
            default: 0
        },
        payoutHistory: [
            {
                amount: { type: Number, required: true },
                date: { type: Date, default: Date.now }
            }
        ]
    },
    reviews: [
        {
            type: Schema.Types.ObjectId,
            ref: "Review"
        }
    ],
    otp: {
        type: Number
    },
    otpExpires: {
        type: Date
    }
}, { timestamps: true });

hostSchema.plugin(passportLocalMongoose, {
    passwordValidator: function (password, cb) {
        if (password.length < 6) {
            return cb("Password must be at least 6 characters long.");
        }
        if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
            return cb("Password must contain at least one special character (!@#$%^&* etc).");
        }
        return cb();
    }
});

module.exports = mongoose.model("Host", hostSchema);
