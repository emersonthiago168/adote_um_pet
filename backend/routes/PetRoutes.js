const router = require('express').Router();
const PetController = require('../controllers/PetController');

// midlewares
const verifyToken = require('../helpers/verify-token');
const { imageUpload } = require('../helpers/image-upload');

router.post('/create', verifyToken, imageUpload.array('images'), PetController.create);


module.exports = router;