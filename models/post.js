const mongoose = require('mongoose');

const postSchema = mongoose.Schema({
    user:{
        type:  mongoose.Schema.Types.ObjectId,
        ref:"user"
    },
    Date: {
        type: Date,
        default:Date.now
    },
    content:{
        type:String,
        required:true
    },
    likes: [
        {type: mongoose.Schema.Types.ObjectId,ref:"user"}
    ]
})

module.exports = mongoose.model('post',postSchema)

