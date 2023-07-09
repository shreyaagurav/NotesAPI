var mysql = require ("mysql");

var connection = mysql.createConnection({
    host : 'localhost',
    database : 'workindia',
    user : 'root',
    password : 'root'
});

module.exports = connection;