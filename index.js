var express = require("express");
var app = express();
var connection = require('./database');
const crypto = require('crypto');
const algorithm = 'aes-256-cbc';
const key = crypto.randomBytes(32); // Generate a random key (32 bytes for AES-256)
const iv = crypto.randomBytes(16);
const {
    v4: uuidv4
  } = require('uuid')
  const bcrypt = require('bcrypt')

const bodyParser = require("body-parser");
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

app.get('/', function(req,res){
    let sql="select * from USER";
    connection.query(sql,function(err,result){
        if(err) console.log(err)
        res.send(result);
    })
});

app.post('/app/user',async(req,res)=>{
    const {username,password}=req.body;
    const saltRounds = 10;
    const encryptedPassword = await bcrypt.hash(password, saltRounds)

    connection.query(
        `INSERT INTO USER(username,password,userid) VALUES (?,?,?)`,[username,encryptedPassword,uuidv4()],(err,result)=>
        {
            if(err){
            console.log(err)
        }
        else{
            res.send({
                status:"Account created"
            })
        }
    }
    )
})

app.post('/app/user/auth',async(req,res)=>{
    const { username, password } = req.body;

    connection.query(
        'SELECT password FROM user WHERE username=?',[username],async(err,result)=>
        {
            console.log(result);
            if(err){
                console.log(err)
            }
            else{
                if(result){
                    const comparison = await bcrypt.compareSync(password,result[0].password)
                    if(comparison){
                        res.send({
                            status : "success"
                        })
                    }else{
                        res.send({
                            status : "declined"
                        })
                    }
                }
            }
        }
    )     
})

app.get('/app/sites/list/:UserID', function(req, res) {
    const {UserID} = req.params;
    console.log('userid:', UserID);
    
    connection.query(
        'SELECT Description FROM notes WHERE UserID=?',[UserID],
        // [UserID],
        async (err, result) => {
            if (err) {
                console.log(err);
                // Handle the error appropriately
                res.status(500).send({
                    status: 'error',
                    message: 'An error occurred while retrieving notes.'
                });
            } else {
                const encryptedDescription = result[0].Description;
                const decipher = crypto.createDecipheriv(algorithm, key, iv);
                let decrypted = decipher.update(encryptedDescription, 'base64', 'utf8');
                decrypted += decipher.final('utf8');
                res.send(decrypted);
            }
        }
    );
});

app.post('/app/sites',async(req,res)=>{
    const UserID = req.query.userid;
    const {Description}=req.body;

    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(Description, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    
    connection.query(
        `INSERT INTO notes(NotesID,Description,UserID) VALUES (?,?,?)`,[uuidv4(),encrypted,UserID],(err,result)=>
        {
            if(err){
            console.log(err)
        }
        else{
            res.send({
                status:"New note created"
            })
        }
    }
    )
})


app.listen(3000, function(){
    console.log('App Listening on port 3000');
    connection.connect(function(err){
        if(err) console.log(err)
        console.log('Database connected!');
    })
});


