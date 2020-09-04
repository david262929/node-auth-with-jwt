const {Router} = require('express')
const {check, validationResult} = require('express-validator')

const auth = require('../middleware/auth.middleware')

const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
require('dotenv').config()

const User = require('../models/User')
const router = Router()

// /api/auth/register
router.post(
    '/register',
    [
        check('name', 'NAME: Min length 6 and max length 255.').isLength({min: 6, max: 255}),
        check('email', 'EMAIL: Min length 6 and max length 255.').isLength({min: 6, max: 255}),
        check('email', 'EMAIL: Not correct email.').isEmail(),
        check('password', 'PASSWORD: Min length 6 and max length 1000.').isLength({min: 6, max: 1024}),
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if ( !errors.isEmpty() ) {
                return res.status(200).json({
                    errors : errors.array(),
                    message: 'Not correct data per register.'
                });
            }

            const {name, email, password} = req.body;

            const candidate = await User.findOne({email});
            if (candidate) {
                return res.status(200).json({message: 'User with that email already exists.'});
            }

            const hashedPassword = await bcrypt.hash(password, 12);
            const newUser = new User({name, email, password: hashedPassword});
            await newUser.save();
            const userId = newUser._id;

            const token = jwt.sign(
                { userId },
                process.env.JWT_SECRET,
                {expiresIn : '10h'}
            );

            res.status(201).json({
                userId,
                token,
                message: 'User created and you logged in.'
            });
        } catch (e) {
            console.log('Dear Developer catched a SERVER ERROR... /api/auth/register ...', e.message, e);
            res.status(500).json({message: 'Something went wrong'});
        }
    }
);

// /api/auth/login
router.post(
    '/login',
    [
        check('email', 'EMAIL: Min length 6 and max length 255.').isLength({min: 6, max: 255}),
        check('email', 'EMAIL: Not correct email.').isEmail(),
        check('password', 'PASSWORD: Min length 6 and max length 1000.').isLength({min: 6, max: 1024}),
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if ( !errors.isEmpty() ) {
                return res.status(400).json({
                    errors : errors.array(),
                    message: 'Not correct data per login.'
                });
            }

            const {email, password} = req.body;

            const currentUser = await User.findOne({email});

            if (!currentUser) {
                return res.status(200).json({message: `Can't find User with that email.`});
            }

            const isMatch = await bcrypt.compare(password, currentUser.password);

            if(!isMatch) {
                return res.status(200).json({message: 'Wrong credentials.'});
            }
            const userId = currentUser._id;

            const token = jwt.sign(
                { userId },
                process.env.JWT_SECRET,
                {expiresIn : '10h'}
            );

            res.status(200).json({
                userId,
                token,
                message: 'Successfully logged In.',
            });


        } catch (e) {
            console.log('Dear Developer catched a SERVER ERROR... /api/auth/login ...', e.message, e);
            res.status(500).json({message: 'Something went wrong'});
        }
    }
);

// /api/auth/register
router.post(
    '/verify',
    auth,
    async (req, res) => res.status(200).json({
        userId : req.user.userId,
        message: 'Authorized',
    })
);

module.exports = router;