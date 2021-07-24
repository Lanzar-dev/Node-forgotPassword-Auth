const dotenv = require("dotenv");
const db = require("./config/database");
const express = require("express");
const cors = require("cors");
const _ = require("lodash");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const auth = require("./middleware/auth");
const mailgun = require("mailgun-js");


const User = require("./model/user"); 

dotenv.config();
db.connect();

const DOMAIN = 'sandbox10d7dd6e6e884e0aa782ab877b6d9f2b.mailgun.org';
const mg = mailgun({apiKey: process.env.MAILGUN_APIKEY, domain: DOMAIN});

const app = express();

app.use(express.json());
app.use(cors());

app.post("/register", async (req, res) => {
    try {
        const {firstName, lastName, email, password} = req.body;

        if(!(email && password && firstName && lastName)) {
            res.status(400).send("All input is required");
        }

        const oldUser = await User.findOne({email});
        if(oldUser) {
            return res.status(409).send("User Already Exist. Please Login");
        }

        encryptedUserPassword = await bcrypt.hash(password, 10);

        const user = await User.create({
            first_name: firstName,
            last_name: lastName,
            email: email.toLowerCase(),
            password: encryptedUserPassword,
        });

        const token = jwt.sign(
            {user_id: user._id, email},
            process.env.TOKEN_KEY,
            {
                expiresIn: "5h",
            }
        );

        user.token = token;
        res.status(201).json(user);
    } catch (error) {
        console.log(error);
    }
});

app.post("/login", async (req, res) => {
    try {
        const {email, password} = req.body;

        if(!(email && password)) {
            res.status(400).send("All input is required");
        }

        const user = await User.findOne({email});

        if(user && (await bcrypt.compare(password, user.password))) {
            const token = jwt.sign(
                {user_id: user._id, email},
                process.env.TOKEN_KEY,
                {
                    expiresIn: "5h",
                }
            );

            user.token = token;

            return res.status(200).json(user);
        }
        return res.status(400).send("Invalid credentials");
    } catch (error) {
        console.log(error);
    }
});

app.post("/welcome", auth, (req, res) => {
    res.status(200).send("Welcome to my site");
});

app.put("/forgot-password", (req, res) => {
    const {email} = req.body;

    User.findOne({email}, (err, user) => {
        if(err || !user) {
            return res.status(400).json({error: "User with this email does not exists."});
        }

        const token = jwt.sign(
            {_id: user._id},
            process.env.RESET_PASSWORD_KEY,
            {
                expiresIn: "5h",
            }
        );
        const data = {
            from: 'noreply@thepowerteam.com',
            to: email,
            subject: 'Password reset link',
            html: `<h2>Please click on given link to reset password</h2>
                    <p>${process.env.CLIENT_URI}/resetpassword/${token}</p>`
        };

        return user.updateOne({resetLink: token}, function(err, success) {
            if(err) {
            return res.status(400).json({error: "Reset password link error."});
            } else {
            mg.messages().send(data, function (error, body) {
                if(error) {
                    return res.json({error: err.message})
                }
                return res.json({message: "Email has been sent. Kindly follow the instructions"});
            });
            }
        });
    });
});

app.put("/reset-password", (req, res) => {
    const {resetLink, newPassword} = req.body;
    if(resetLink) {
        jwt.verify(resetLink, process.env.RESET_PASSWORD_KEY, function(error, decodedData) {
            if(error) {
            return res.status(401).json({error: "Incorrect token or it is expired."});
            }
            User.findOne({resetLink}, (err, user) => {
                if(err || !user) {
                return res.status(400).json({error: "User with this token does not exist."});
                }

                //encrypt the reset password
                // encryptedUserPassword = bcrypt.hash(newPassword, 10);

                const obj = {
                    password: newPassword,
                    resetLink: ''
                }

                user = _.extend(user, obj);
                user.save((err, result) => {
                    if(err) {
                    return res.status(400).json({error: "Reset password error."});
                    } else {
                        return res.status(200).json({message: "Your password has been changed"});                
                    }
                })
            })
        });
    } else {
        return res.status(401).json({error: "Authentication error!!!."});
    }
})

module.exports = app;