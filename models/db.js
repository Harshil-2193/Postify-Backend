const mongoose = require('mongoose');
const dotenv = require('dotenv');
dotenv.config()

module.exports =  connectDb = async () =>{
    try{
        await mongoose.connect(process.env.MONGODB_URI)
        console.log("MongoDb Connected");
        

    }
    catch(err){
        console.log(err.message);
        process.exit(1);
    }
}