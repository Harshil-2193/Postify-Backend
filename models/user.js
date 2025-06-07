const mongoose = require('mongoose');

const userSchema = mongoose.Schema({
    username:{
        type: String,
        required: [true, 'Username required'],
        unique: true,
        maxlength: 20,
        minlength: 3,
        trim: true
    },
    name:{
        type: String,
        required: [true, 'Name is required'],
        maxlength: 50,
        trim: true
    },
    age:{
        type: Number,
        min: 13,
        max: 120,
        required: [true, 'Age is required']
    },
    email:{
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        maxlength: 100,
        trim: true,
        match: [/.+\@.+\..+/, 'Please enter a valid email address']
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: 3
    }
})

module.exports = mongoose.model('user',userSchema)

