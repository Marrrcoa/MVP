const express = require('express');
const dotenv= require('dotenv')
const cookieParser = require('cookie-parser')

const app= express()

//seteamos el motor de plantillas

app.set('view engine', 'ejs')

//seteamos la carpeta public para los archivos estaticos
app.use(express.static('public'))

//para procesar datos enviados desde forms
app.use(express.urlencoded({extended:true}))
app.use(express.json())

//seteamos las variables de entorno
dotenv.config({path: './env/.env'})

//para trabajar con cookies
app.use(cookieParser())

//llamar al router principal
app.use('/', require('./routes/router'))

//Para eliminar el cache y que no se pueda volver con el boton de back Luego de que hacemos un LOGOUT
app.use(function(req, res, next) {
    if (!req.user)
    res.header('Cache-Control', 'private, no-cache, no-store, must-revalidate');
    next();
    });



app.listen(3000, ()=>{
    console.log('server up ruunin in http://localhost:3000')
})
