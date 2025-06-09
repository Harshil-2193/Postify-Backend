const express = require('express');
const app = express();
const dotenv = require('dotenv');
const connectDb = require('./models/db')
const userModel = require('./models/user')
const cookieParser = require("cookie-parser")
const userRoutes = require('./routes/userRoutes');
const path = require('path');

dotenv.config();
const PORT = process.env.PORT;

connectDb();
app.set('view engine', 'ejs')
app.use(express.json())
app.use(express.urlencoded({extended:true}))
app.use(cookieParser());
app.use(express.static(path.join(__dirname,'public')));


app.use('/user', userRoutes);


app.listen(PORT, ()=>{
    console.log(`Server is running on port${PORT} `);
})