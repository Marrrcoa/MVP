const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

// Rutas para las vistas
router.get('/', authController.isAuthenticated, (req, res) => {
    res.render('index');
});

router.get('/productos', authController.isAuthenticated, (req, res) => {
    res.render('productos');
});

router.get('/login', (req, res) => {
    res.render('login', { alert: false });
});

router.get('/register', (req, res) => {
    res.render('register');
});

// Nueva ruta para obtener todos los usuarios, protegida por el middleware de autenticación y verificación de administrador
router.get('/trabajadores', authController.isAuthenticated, authController.isAdmin, authController.getAllUsers);

// Rutas para el controlador
router.post('/register', authController.register);
router.post('/login', authController.login);
router.get('/logout', authController.logout);

// Rutas para actualizar y borrar usuarios, protegidas por el middleware de autenticación
router.post('/update-user', authController.isAuthenticated, authController.isAdmin, authController.updateUser);
router.post('/delete-user', authController.isAuthenticated, authController.isAdmin, authController.deleteUser);

module.exports = router;
