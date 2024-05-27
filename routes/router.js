const express= require('express')
const router = express.Router()


const authController = require('../controllers/authController')

//router para las vistas
router.get('/', authController.isAuthenticated, (req, res)=>{
    res.render('index')
})

router.get('/login', (req, res)=>{
    res.render('login', {alert:false})
})

router.get('/register', (req, res)=>{
    res.render('register')
})

// Nueva ruta para obtener todos los usuarios
router.get('/trabajadores', authController.getAllUsers);

//router para el controler
router.post('/register',authController.register)
router.post('/login',authController.login)
router.get('/logout',authController.logout)
module.exports = router