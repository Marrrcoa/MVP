const mysql = require('mysql');
const config = require('./config');

const conexion = mysql.createConnection({
  host: config.db.host,
  user: config.db.user,
  password: config.db.password,
  database: config.db.database
});

conexion.connect((error) => {
  if (error) {
    console.log('El error de conexión es: ' + error);
    return;
  }
  console.log('Conectado a la base de datos');
});

module.exports = conexion;