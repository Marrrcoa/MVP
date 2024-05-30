const jwt = require('jsonwebtoken');
const bcryptjs = require('bcryptjs');
const conexion = require('../database/db');
const { promisify } = require('util');
const { error } = require('console')
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

exports.register = async (req, res) => {
    try {
        const { name, user, pass} = req.body;
        const passHash = await bcryptjs.hash(pass, 8);

        // Generar una clave secreta para 2FA
        const secret = speakeasy.generateSecret({ length: 20 });

        // Guardar el usuario con la clave secreta
        conexion.query('INSERT INTO users SET ?', { user, name, pass: passHash, twofactor_secret: secret.base32}, (error, results) => {
            if (error) {
                console.log(error);
                res.status(500).send('Error al registrar usuario');
            } else {
                // Generar un QR Code para la clave secreta
                qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
                    if (err) {
                        console.log(err);
                        res.status(500).send('Error al generar código QR');
                    } else {
                        // Asegurarse de pasar el QR code a la vista de registro
                        res.render('register', { qr_code: data_url });
                    }
                });
            }
        });
    } catch (error) {
        console.log(error);
        res.status(500).send('Error interno del servidor');
    }
};


exports.login = async (req, res) => {
    try {
        const user = req.body.user;
        const pass = req.body.pass;
        const token2FA = req.body.token; // código 2FA ingresado por el usuario

        if (!user || !pass || !token2FA) {
            return res.render('login', {
                alert: true,
                alertTitle: "Advertencia",
                alertMessage: "Ingrese usuario, password y código 2FA",
                alertIcon: 'info',
                showConfirmButton: true,
                timer: false,
                ruta: 'login'
            });
        }

        conexion.query('SELECT * FROM users WHERE user = ?', [user], async (error, results) => {
            if (results.length == 0 || !(await bcryptjs.compare(pass, results[0].pass))) {
                return res.render('login', {
                    alert: true,
                    alertTitle: "Advertencia",
                    alertMessage: "Usuario o password incorrectos",
                    alertIcon: 'info',
                    showConfirmButton: true,
                    timer: false,
                    ruta: 'login'
                });
            }

            // Verificar el código 2FA
            const verified = speakeasy.totp.verify({
                secret: results[0].twofactor_secret,
                encoding: 'base32',
                token: token2FA
            });

            if (!verified) {
                return res.render('login', {
                    alert: true,
                    alertTitle: "Advertencia",
                    alertMessage: "Código 2FA incorrecto",
                    alertIcon: 'info',
                    showConfirmButton: true,
                    timer: false,
                    ruta: 'login'
                });
            }

            // Si la verificación es exitosa, proceder con el inicio de sesión
            const id = results[0].id;
            const jwtToken = jwt.sign({ id: id }, process.env.JWT_SECRETO, {
                expiresIn: process.env.JWT_TIEMPO_EXPIRA
            });

            const cookiesOption = {
                expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
                httpOnly: true
            };
            res.cookie('jwt', jwtToken, cookiesOption);
            res.render('login', {
                alert: true,
                alertTitle: "Conexión exitosa!",
                alertMessage: "LOGIN exitoso",
                alertIcon: 'success',
                showConfirmButton: false,
                timer: 800,
                ruta: '/'
            });
        });
    } catch (error) {
        console.log(error);
    }
};


exports.isAuthenticated = async (req, res, next) => {
    if (req.cookies.jwt) {
        try {
            const decoded = await promisify(jwt.verify)(req.cookies.jwt, process.env.JWT_SECRETO);
            conexion.query('SELECT * FROM users WHERE id = ?', [decoded.id], (error, results) => {
                if (!results) {
                    return next();
                }
                req.user = results[0];
                return next();
            });
        } catch (error) {
            console.log(error);
            return next();
        }
    } else {
        res.redirect('/login');
    }
};

exports.isAdmin = (req, res, next) => {
    if (req.user && req.user.isAdmin) {
        return next();
    } else {
        res.status(403).render('no-permission');
    }
};

exports.logout = (req, res) => {
    res.clearCookie('jwt');
    return res.redirect('/');
};

// Nueva función para obtener todos los usuarios
exports.getAllUsers = (req, res) => {
    conexion.query('SELECT * FROM users', (error, results) => {
        if (error) {
            console.log(error);
            res.status(500).send('Error al obtener los usuarios.');
        } else {
            res.render('trabajadores', { users: results });
        }
    });
};

// Función para actualizar un usuario
exports.updateUser = (req, res) => {
    const { id, name, user } = req.body;
    conexion.query('UPDATE users SET name = ?, user = ? WHERE id = ?', [name, user, id], (error, results) => {
        if (error) {
            console.log(error);
            res.status(500).send('Error al actualizar el usuario.');
        } else {
            res.send({ id, name, user });
        }
    });
};

// Función para borrar un usuario
exports.deleteUser = (req, res) => {
    const { id } = req.body;
    conexion.query('DELETE FROM users WHERE id = ?', [id], (error, results) => {
        if (error) {
            console.log(error);
            res.status(500).send('Error al borrar el usuario.');
        } else {
            res.send({ id });
        }
    });
};
