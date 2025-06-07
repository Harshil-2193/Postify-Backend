const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');

const userModel = require('../models/user');
const postModel = require('../models/post');
const jwt = require('jsonwebtoken');

router.get('/', (req,res)=>{
    res.render("register",{errMsg:null,successMsg:null});  
});

// Register User
router.post('/register', async (req,res)=>{
    const {name, username, email, password, confirmPassword, age} = req.body;

    // Field Validation
    if(!name || !username || !email || !age || !password)
        return res.render("register", {errMsg:"All fields are require", successMsg:null});

    // Password Match Check
    if(password !== confirmPassword)
        return res.render("register",{errMsg: "Password do not match.", successMsg:null});
    
    // Strong strength
    const isStrong = password.length >= 4 && /\d/.test(password) && /[A-Z]/.test(password);
    if (!isStrong) 
        return res.render("register", { errMsg: "Password must be at least 4 characters long, include 1 uppercase and 1 number", successMsg: null });
    
    try{
        // Check if Email Exists
        const existingUser = await userModel.findOne({email});
        if(existingUser)
            return res.render("register", {errMsg: "User Already Exists",successMsg:null});

        // Check if Username Exists
        const existingUserName = await userModel.findOne({username});
        if(existingUserName)
            return res.render("register", {errMsg: "UserName Already Taken",successMsg:null});

        // Secure password
        const hashedpass = await securePass(password);

        
        // Create User
        const newUser = await userModel.create({name, username, email, password:hashedpass, age});

        //  JWT Token
        let token = jwt.sign({email, userid:newUser._id},process.env.JWT_SECRET,{expiresIn:'1d'});
        res.cookie('token',token,{httpOnly:true});
        await newUser.save();

        return res.render("register",{errMsg:null,successMsg: "Accont Create Successfully."});
    }
    catch(err){
        console.log(err.message);
        return res.status(500).render("register",{errMsg: "Internal Server Error",successMsg:null});
    }    
});

// Login User
router.get('/login',(req,res)=>{
    res.render("login",{errMsg:req.query.msg || null, successMsg: req.query.success || null});
});
// Login User
router.post('/login',async (req,res)=>{
    const {username, password} = req.body;

    try{

        let user = await userModel.findOne({username});
        if(!user) return res.render('login', {errMsg:"Account is not avaiable with this username", successMsg:null});
        
        // Compare passwords using bcrypt
        const isMatch = await bcrypt.compare(password,user.password);
        if(!isMatch) return res.render('login', {errMsg:"Incorrect Password", successMsg:null});
        
        // If matched, generate token
        const token = jwt.sign({userId:user._id, email:user.email}, process.env.JWT_SECRET);
        res.cookie('token',token);
        return res.redirect('/profile');
    }catch(err){
        console.log(err.message);
        return res.status(500).render('login', { errMsg: "Internal Server Error", successMsg: null });
    }
});


// LogOut
router.get('/logout',(req,res)=>{
    res.clearCookie('token');
    res.redirect("/user/login?success=Logged out successfully");
});

// MiddleWare For Login check
const isLoggedIn = (req, res, next)=>{
    if(!req.cookies.token) 
        res.redirect("/user/login?msg=User must be logged in");
    else{
       req.user = jwt.verify(req.cookies.token, process.env.JWT_SECRET);
       next();
    }
}

router.get('/profile',isLoggedIn,(req,res)=>{
    console.log(req.user);
    res.render("profile");
});

const securePass = async (password)=> {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password,salt);
}


module.exports = router;