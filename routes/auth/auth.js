let express = require('express');
const User = require("../../models/user_model");
let router = express.Router();
let path=require('path');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');
const TOKEN_KEY = "2AouR3eCDQTIR0FU2eMezf3OpWvEt88z";

//api za registraciju
router.post("/register", async (req, res) => {    
    try {
      const { username, email, password, is_admin } = req.body;
      if (!(email && password && username)) {
        res.status(400).send("All input is required");
      }
  
      // Provera da li korisnik vec postoji sa istim emailom
      const oldUser = await User.findOne({ email });
  
      //Ako korsinik sa isim emailom postoji ne mozemo da napravimo novog
      if (oldUser) {
        return res.status(409).send("User Already Exist. Please Login");
      }
  
      //Enkriptovanje sifre
      encryptedPassword = await bcrypt.hash(password, 10);
  
      // Kreiranje korisnika u bazi
      const user = await User.create({
        username,
        email: email.toLowerCase(), // sanitize: convert email to lowercase
        password: encryptedPassword,
        is_admin
      });
  
      // Kreiranje tokena
      const token = jwt.sign(
        { user_id: user._id, email },
        TOKEN_KEY,
        {
          expiresIn: "2h",
        }
      );
      // pamcenje tokena
      user.token = token;
      await user.save();
  
      // Vracanje novog korisnika
      res.status(201).json(user);
    } catch (err) {
      console.log(err);
    }
    // Ovde se zavrsava logika registracije
  });

  //API za login
  router.post("/login",async (req, res) => {
    try {
        
        const { email, password } = req.body;
    
        // Validiranje ulaznih podataka
        if (!(email && password)) {
          res.status(400).send("All input is required");
        }
        // Validate if user exist in our database
        const user = await User.findOne({ email });
    
        if (user && (await bcrypt.compare(password, user.password))) {
          // kreiramo token
          const token = jwt.sign(
            { user_id: user._id, email },
            TOKEN_KEY,
            {
              expiresIn: "2h",
            }
          );
    
          // pamtimo novi token za korisnika
          user.token = token;
          await user.save();
    
          // vracamo korisnika koji se upravo ulogovao
          res.status(200).json(user);
        }else{
          res.status(400).send("Invalid Credentials");
        }
      } catch (err) {
        console.log(err);
      }
    });

module.exports = router;