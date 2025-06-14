const multer = require('multer');
const path = require('path');
const crypto = require('crypto');

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/IMAGES/uploads'); // Make sure this path exists
  },

  filename: function (req, file, cb) {
    crypto.randomBytes(12, (err, bytes) => {
      if (err) return cb(err);
      const fileName = bytes.toString('hex') + path.extname(file.originalname);
      cb(null, fileName);
    });
  }
});

const upload = multer({ storage: storage });

module.exports = upload;
