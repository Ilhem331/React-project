const express = require("express");
const cookieSession = require("cookie-session");
require("dotenv").config();
const app = express();
const mongoose = require("mongoose");
app.use(express.json());
const cors = require("cors");
const bcrypt = require("bcryptjs");
const auth = require("./authenticate");
require("./userDetails");
const validateRegisterInput = require("./register");
const validateLoginInput = require("./login");
const emailValidator = require('deep-email-validator');
const stripe = require('stripe')('sk_test_51MqBW0DibfZFFh9BmXYPguMX6fdIX0g9r8fugwJythxXqRttJbBQitAApQEZPObQbGNbw9CS4iLNTSOuumVjw0p100SC1jpMRW')
const request = require('request');
const multer = require("multer");
const fs = require("fs");
const axios = require("axios");
const https = require("https");
const { v4: uuidv4 } = require('uuid');
const path = require('path'); 



app.use("/uploads", express.static("uploads"));

 const yearly = 'price_1MveVIDibfZFFh9B2VTurN1N';
 const monthly = 'price_1MveYxDibfZFFh9Bp67l0Pr6';


async function isEmailValid(email) {
  return emailValidator.validate(email)
}

app.use(
	cors({
		origin: "http://localhost:8080",
		methods: "GET,POST,PUT,DELETE,PATCH",
		credentials: true,
	})
);



const jwt = require("jsonwebtoken");
var nodemailer = require("nodemailer");


 const jwtSecret = 'fasefraw4r5r3wq45wdfgw34twdfg';

const mongoUrl =
  "mongodb+srv://IlhemAf:Ilhem123456789@cluster0.ca6pp1l.mongodb.net/?retryWrites=true&w=majority";
mongoose.set("strictQuery", false);
mongoose
  .connect(mongoUrl, {
    useNewUrlParser: true,
    useUnifiedTopology: true, 
    
    
  })
  
  .then(() => {
    console.log("Connected to database");
  })
  .catch((e) => console.log(e));


 
const User = mongoose.model("users");


async function getAiResponse(prompt) {
  const openai = new OpenAIApi(configuration);
  const completion = await openai.createCompletion({
    model: "text-davinci-002",
    prompt: prompt,
    max_tokens: 100,
    n: 1,
    stop: null,
    temperature: 0.7
  });
  console.log(completion.data.choices[0].text);
}

app.post('/chatgpt', async (req, res) => {
  const prompt = req.body.prompt;
  try {
    if (!prompt) {
      res.status(400).json({
        status: "400",
        message: "No prompt was provided",
      });
      return;
    }
    
    const completion = await getAiResponse(prompt);
    res.status(200).json({
      success: true,
      message: completion,
    });
  } catch (error) {
    console.log(error.message);
    res.status(500).send('Internal Server Error');
  }
});

app.post("/register", async (req, res) => {
  try {
    const { errors, isValid } = validateRegisterInput(req.body);
    if (!isValid) {
      return res.status(400).json(errors);
    }
    let { username, email, password, pic, coverpic, bio } = req.body;
    // validate
    if ( !username || !email || !password ) 
    return res.send({ code:404, msg: "Not all fields have been entered." });
    if (password.length < 5)
    return res
    .status(402)
    .json({ msg: "The password needs to be at least 5 characters long." });
    const {valid, reason, validators} = await isEmailValid(email);
    if (!valid)
    return res.send({ code:400,
      message: "Please provide a valid email address.",
      reason: validators[reason].reason
    })
    const existingUser = await User.findOne({ email: email });
    if (existingUser) {
    return res.send
    ({code:402, msg: "An account with this email already exists." });
  } else {
    const salt = await bcrypt.genSalt();
    const passwordHash = await bcrypt.hash(password, salt);
    const newUser = new User({
    username,
    email,
    password: password,
    pic,
    coverpic,
    bio,
  
    });
    const savedUser = await newUser.save();
      return res.send
    ({code:200, msg: "User signed up" });
    }
    } catch (err) {
    res.status(500).json({ error: err.message });
    }
    });


app.post("/login-user", async (req, res) => {
  try {
    const { errors, isValid } = validateLoginInput(req.body);
// Check validation

  if (!isValid) {
    return res.status(400).json(errors);
  }
    const { email, password } = req.body;
    // validate
    if (!email || !password)
    return res.send({ code:404, msg: "Not all fields have been entered." });
    const user = await User.findOne({ email: email, password: password });
    if (!user)
     return res.send({code:400, msg: "Invalid credentials." });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.send({
    code : 200,
    message: 'User found',
    token,
    id: user._id,
    username: user.username,
    pic: user.pic,
    coverpic: user.coverpic,
    bio: user.bio,
   
 
    });
    } catch (err) {
    res.send({ code:400, error: err.message });
    }
    });





    app.get('/user/info', auth, async (req, res) => {
      try {
        const user = await User.findById(req.user.id).select('-password');
        res.status(200).json({ user });
      } catch (error) {
        res.status(500).json(error);
    }
    });
     


    app.post("/store-image", async (req, res) => {
  try {
    const { image } = req.body;
    if (!image) {
      return res.status(400).json({ msg: "Please enter an icon url" });
    }
    let newImage = new Image({
      image,
    });
    newImage = await newImage.save();
    res.json(newImage);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});





  
    app.post("/change-password", async (req, res) => {
      const { password, password_confirmation } = req.body
      if (password && password_confirmation) {
        if (password !== password_confirmation) {
          res.send({ "status": "failed", "message": "New Password and Confirm New Password doesn't match" })
        } else {
          const salt = await bcrypt.genSalt(10)
          const newHashPassword = await bcrypt.hash(password, salt)
          await User.findByIdAndUpdate(req.user._id, { $set: { password: newHashPassword } })
          res.send({ "status": "success", "message": "Password changed succesfully" })
        }
      } else {
        res.send({ "status": "failed", "message": "All Fields are Required" })
      }
    })
    app.get("/loggeduser", async (req, res) => {
      res.send({ "user": req.user })
    })

    app.get('/myprofile',auth,async(req, res)=>{
      try{
          let exist = await User.findById(req.user.id);
          if(!exist){
              return res.status(400).send('User not found');
          }
          res.json(exist);
      }
      catch(err){
          console.log(err);
          return res.status(500).send('Server Error')
      }
  })
    app.delete("/delete", auth, async (req, res) => {
      try {
      const deletedUser = await User.findByIdAndDelete(req.user);
      res.json(deletedUser);
      } catch (err) {
      res.status(500).json({ error: err.message });
      }
      });
      app.delete("/reset-email", auth, async (req, res) => {
        const { email } = req.body
        if (email) {
          const user = await User.findOne({ email: email })
          if (user) {
            const secret = user._id + process.env.JWT_SECRET_KEY
            const token = jwt.sign({ userID: user._id }, secret, { expiresIn: '15m' })
            const link = `http://127.0.0.1:8080/api/user/reset/${user._id}/${token}`
            console.log(link)
            // // Send Email
            // let info = await transporter.sendMail({
            //   from: process.env.EMAIL_FROM,
            //   to: user.email,
            //   subject: "GeekShop - Password Reset Link",
            //   html: `<a href=${link}>Click Here</a> to Reset Your Password`
            // })
            res.send({ "status": "success", "message": "Password Reset Email Sent... Please Check Your Email" })
          } else {
            res.send({ "status": "failed", "message": "Email doesn't exists" })
          }
        } else {
          res.send({ "status": "failed", "message": "Email Field is Required" })
        }
      })

      app.delete("/reset-password", auth, async (req, res) => {
    const { password, password_confirmation } = req.body
    const { id, token } = req.params
    const user = await User.findById(id)
    const new_secret = user._id + process.env.JWT_SECRET_KEY
    try {
      jwt.verify(token, new_secret)
      if (password && password_confirmation) {
        if (password !== password_confirmation) {
          res.send({ "status": "failed", "message": "New Password and Confirm New Password doesn't match" })
        } else {
          const salt = await bcrypt.genSalt(10)
          const newHashPassword = await bcrypt.hash(password, salt)
          await UserModel.findByIdAndUpdate(user._id, { $set: { password: newHashPassword } })
          res.send({ "status": "success", "message": "Password Reset Successfully" })
        }
      } else {
        res.send({ "status": "failed", "message": "All Fields are Required" })
      }
    } catch (error) {
      console.log(error)
      res.send({ "status": "failed", "message": "Invalid Token" })
    }
  })
  

    
      // Check if token is valid
      app.post("/tokenIsValid", async (req, res) => {
      try {
      const token = req.header("x-auth-token");
      if (!token) return res.json(false);
      const verified = jwt.verify(token, process.env.JWT_SECRET);
      if (!verified) return res.json(false);
      const user = await User.findById(verified.id);
      if (!user) return res.json(false);
      return res.json(true);
      } catch (err) {
      res.status(500).json({ error: err.message });
      }
      });
      app.get("/", auth, async (req, res) => {
      const user = await User.findById(req.user);
      res.json({
      username: user.username,
      email: user.email,
      id: user._id,
      pic: user.pic,
      coverpic: user.coverpic,
      bio: user.bio,

      });
      });
    
      app.get("/getuser/:id",async(req,res)=>{
        try {
            console.log(req.params);
            const {id} = req.params;
    
            const userindividual = await User.findById({_id:id});
            console.log(userindividual);
            res.status(201).json(userindividual)
    
        } catch (error) {
            res.status(422).json(error);
        }
    })

    app.patch('/update-user/:id', async (req,res) => {
      const updatedUser = await User.findByIdAndUpdate(req.params.id,req.body,{
          new : true,
          runValidators : true
        })
      try{
          res.status(200).json({
              status : 'Success',
              data : {
                updatedUser
              }
            })
      }catch(err){
          console.log(err)
      }
  })



  app.patch("/updatedduser/:id",async(req,res)=>{
    try {
        const {id} = req.params;

        const updateduser = await User.findByIdAndUpdate(id,req.body,{
            new:true
        });

        console.log(updateduser);
        res.status(201).json(updateduser);

    } catch (error) {
        res.status(422).json(error);
    }
})

      app.post("/updateUser", async(req, res) => {
        const id = req.params.id;
        const username = req.body.username;
        const email = req.body.email;
        const pic = req.body.pic;
        const coverpic = req.body.coverpic;
        const bio = req.body.bio;
        
        
  try {
    
     const user = await User.findOneAndUpdate(
      id,
      { "$set": {
      "username": username,
      "email": email,
      "pic": pic,
      "coverpic": coverpic,
      "bio":bio,
    }
      }
      
     
    );

    res.send({ code:200, msg:"update successful"});
  } catch (error) {
    // ...
  }
});
     


app.post("/updateUserId", async(req, res) => {
  const id = req.params.id;
  const user = await User.findById(id) ;
  if (!id) {
    res.send({ code:500, msg:"user not found"});
  }

  if (user) {
    user.username = req.body.username || user.username;
    user.email = req.body.email || user.email;
    user.pic = req.body.pic || user.pic;
    user.coverpic = req.body.coverpic || user.coverpic;
    user.bio = req.body.bio || user.bio;


    const updatedUser = await user.save();

res.send({ code:200, msg:"update successful"});

  }else {
    res.status(404);
  // ...
}

  

})



app.put('/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    user.username = req.body.username;
    user.email = req.body.email;
  
    const updatedUser = await user.save();
    res.json(updatedUser);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

app.put('/api/user/:id', auth, async (req, res) => {
  const userId = req.params.id;
  if (userId !== req.user) {
    return res.status(403).json({ message: 'You are not authorized to perform this action' });
  }
  try {
    const updatedUser = await User.findByIdAndUpdate(userId, req.body, { new: true });
    return res.json(updatedUser);
  } catch (error) {
    return res.status(500).json({ message: 'Failed to update user profile' });
  }
});



app.post("/updateById", async(req, res) => {
  const token = req.header("x-auth-token");
      if (!token) return res.json(false);
      const verified = jwt.verify(token, process.env.JWT_SECRET);
      id = verified.id;
      const options = { new: true };
  const username = req.body.username;
  const email = req.body.email;
  const pic = req.body.pic;
  const coverpic = req.body.coverpic;
  const bio = req.body.bio;
      const user = User.findByIdAndUpdate(id, { "$set": {
        "username": username,
        "email": email,
        "pic": pic,
        "coverpic": coverpic,
        "bio":bio,
      }
        } , options, (err, user) => {
        if (err) {
          console.error(err);
          return;
        }  
         res.send({ code:200, msg:"User updated successfully!"});
        console.log(user);
      });
     


    })
        
    
     
     
 



app.post('/updateMult', (req, res) => {
  const id = req.body.id;
  
  User.findById(id, (err, user) => {
    if (err) {
      console.log(err);
      return res.status(500).send(err);
    }

    user.username = req.body.username || user.username;
    user.email = req.body.email || user.email;

    user.save((err) => {
      if (err) {
        console.log(err);
        return res.status(500).send(err);
      }

      return res.send('User updated successfully');
    });
  });
});


app.post('/create-checkout-session', async (req, res) => {
  const session = await stripe.checkout.sessions.create({
    line_items: [
      {
        price: 'price_1MveYxDibfZFFh9Bp67l0Pr6',
        quantity: 1,
      },
    ],
    mode: 'subscription',
    success_url: 'http://localhost:5000/success',
    cancel_url: 'http://localhost:8080/profile',
  });

  res.redirect(303, session.url);
});

app.post('/create-session', async (req, res) => {
  const session = await stripe.checkout.sessions.create({
    line_items: [
      {
        price: 'price_1MveVIDibfZFFh9B2VTurN1N',
        quantity: 1,
      },
    ],
    subscription_data: {
      trial_period_days:3

    },
    mode: 'subscription',
    success_url: 'http://localhost:5000/success',
    cancel_url: 'http://localhost:8080/profile',
  });

  res.redirect(303, session.url);
});


app.get('/success', async (req, res) => {
  

  res.send(`<html><body><h1>Thank you for your subscription!</h1></body></html>`);
});


app.post('/create-payment-Intents', async (req, res) => {
const paymentIntent = await stripe.checkout.sessions.create({
  unit_amount: 500,
  currency: 'gbp',
  payment_method_types: 'pm_card_visa',
});
res.redirect(301, paymentIntent.url);
});



app.get('/success', async (req, res) => {
  const session = await stripe.checkout.sessions.retrieve(req.query.session_id);
  const customer = await stripe.customers.retrieve(session.customer);

  res.send(`<html><body><h1>Thanks for your order, ${customer.name}!</h1></body></html>`);
});


app.get('/success-email', async (req, res) => {
const invoice = await stripe.invoices.sendInvoice('id');
})


app.get('https://buy.stripe.com/test_7sI4hreDD2v8guseUW', async (req, res) => {
  const session = await stripe.checkout.sessions.create({
    success_url: 'http://localhost:5000/success',
    cancel_url: 'http://localhost:8080/profile',
  });

  })





app.get('https://buy.stripe.com/test_9AQ5lv8ff3zcgus289', async (req, res) => {

})


app.get('billing.stripe.com/p/login/test_8wM5nNdsc5ob5vaeUU', async (req, res) => {

})


app.get('/:id',  (req, res) => {
  User.findById(req.params.id)
    .then(user => res.json(user))
    .catch(err => res.status(404).json({ nouserfound: 'No User found' }));
});



app.get('/uuser/id', auth, (req, res) => {
  return res.json({ userId: req.user });
});



app.put('profilee/:id', (req, res) => {
  const username = req.body.username;
  const email = req.body.email;
  const pic = req.body.pic;
  const coverpic = req.body.coverpic;
  const bio = req.body.bio;
  User.findByIdAndUpdate(req.params.id, { "$set": {
    "username": username,
    "email": email,
    "pic": pic,
    "coverpic": coverpic,
    "bio":bio,
  }})
    .then(user => res.json({ msg: 'Updated successfully' }))
    .catch(err =>
      res.status(400).json({ error: 'Unable to update the Database' })
    );
});


app.post('/api/generate-images', async (req, res) => {
  try {
    const { prompt } = req.body;
    const apiUrl = 'https://stablediffusionapi.com/api/v3/text2img';
    const apiKey = "Z8g0l2PHJiazwGZchTwDF3TsEKOVd0QCJXaQ04pmDQK9UGqTAiAtkwy34mxh";


    const payload = {
      key: apiKey,
      prompt,
      negative_prompt: null,
      width: "512",
      height: "512",
      samples: "2",
      steps: "50",
      seed: null,
      guidance_scale: 7.5,
      safety_checker: "yes",
      multi_lingual: "no",
      panorama: "no",
      self_attention: "no",
      upscale: "no",
      embeddings_model: "embeddings_model_id",
      webhook: null,
      track_id: null
    };

    const response = await axios.post(apiUrl, payload);
    console.log(response.data); // Log the response body

    res.json(response.data); // Send the response back to the client
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong' });
  }
});


app.post('/generate-image', async (req, res) => {
  try {
    const { prompt, init_image} = req.body;
    const apiUrl = 'https://stablediffusionapi.com/api/v3/img2img';
    const apiKey = "Z8g0l2PHJiazwGZchTwDF3TsEKOVd0QCJXaQ04pmDQK9UGqTAiAtkwy34mxh";


    const payload = {
      key: apiKey,
      prompt,
      init_image,
      negative_prompt: null,
      width: "512",
      height: "512",
      samples: "2",
      num_inference_steps: "20",
      seed: null,
      guidance_scale: 7.5,
      safety_checker: "yes",
      multi_lingual: "no",
      panorama: "no",
      self_attention: "no",
      upscale: "no",
      embeddings_model: "embeddings_model_id",
      webhook: null,
      track_id: null
    };

    const response = await axios.post(apiUrl, payload);
    console.log(response.data); // Log the response body

    res.json(response.data); // Send the response back to the client
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/'); // Directory to save uploaded images
  },
  filename: function (req, file, cb) {
    const fileName = file.originalname;
    cb(null, fileName);
  }
});

const upload = multer({ storage: storage });

app.post('/generate-image', async (req, res) => {
  try {
    // ...
    
    // Upload the image to the crop API
    const cropOptions = {
      method: 'POST',
      url: 'https://stablediffusionapi.com/api/v3/base64_crop',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        "key": "Z8g0l2PHJiazwGZchTwDF3TsEKOVd0QCJXaQ04pmDQK9UGqTAiAtkwy34mxh",
        "image": `data:image/png;base64,${imageContent}`,
        "crop": "true"
      })
    };

    const cropResponse = await axios(cropOptions);
    console.log(cropResponse.data); // Log the crop API response

    // Use the output image URL from the crop API as the init_image for the image-to-image API
    const init_image = cropResponse.data.link;

    // Call the image-to-image API with the prompt and init_image
    const img2imgUrl = 'https://stablediffusionapi.com/api/v3/img2img';
    const img2imgApiKey = "YOUR_IMAGE_TO_IMAGE_API_KEY";

    const img2imgPayload = {
      key: img2imgApiKey,
      prompt,
      init_image,
      // Other parameters...
    };

    const img2imgResponse = await axios.post(img2imgUrl, img2imgPayload);
    console.log(img2imgResponse.data); // Log the image-to-image API response

    res.json(img2imgResponse.data); // Send the response back to the client
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong' });
  }
});


app.post('/api/generate-image', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      res.status(400).json({ error: 'No file uploaded' });
      return;
    }

    const { prompt } = req.body;
    const cropApiUrl = 'https://stablediffusionapi.com/api/v3/base64_crop';
    const img2imgApiUrl = 'https://stablediffusionapi.com/api/v3/img2img';
    const apiKey = "Z8g0l2PHJiazwGZchTwDF3TsEKOVd0QCJXaQ04pmDQK9UGqTAiAtkwy34mxh";
    
    // Upload the image to the Crop API
    const imagePath = req.file.path;
    const imageContent = fs.readFileSync(imagePath, { encoding: 'base64' });
    const cropOptions = {
      method: 'POST',
      url: cropApiUrl,
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        "key": apiKey,
        "image": `data:image/png;base64,${imageContent}`,
        "crop": "true"
      })
    };
    const cropResponse = await axios(cropOptions);
    const outputImage = cropResponse.data.output_image;

    // Call the Image-to-Image API with the prompt and the output image from the Crop API
    const img2imgPayload = {
      key: apiKey,
      prompt,
      init_image: outputImage,
      negative_prompt: null,
      width: "512",
      height: "512",
      samples: "2",
      num_inference_steps: "20",
      seed: null,
      guidance_scale: 7.5,
      safety_checker: "yes",
      multi_lingual: "no",
      panorama: "no",
      self_attention: "no",
      upscale: "no",
      embeddings_model: "embeddings_model_id",
      webhook: null,
      track_id: null
    };
    const img2imgOptions = {
      method: 'POST',
      url: img2imgApiUrl,
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(img2imgPayload)
    };
    const img2imgResponse = await axios(img2imgOptions);

    res.json(img2imgResponse.data); // Send the response back to the client
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong' });
  }
});


app.post('/api/base64_crop', upload.single('image'), (req, res) => {
  try {
    const imagePath = req.file.path;
    const imageContent = fs.readFileSync(imagePath, { encoding: 'base64' });

    const cropOptions = {
      method: 'POST',
      url: 'https://stablediffusionapi.com/api/v3/base64_crop',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        "key": "Z8g0l2PHJiazwGZchTwDF3TsEKOVd0QCJXaQ04pmDQK9UGqTAiAtkwy34mxh",
        "image": `data:image/png;base64,${imageContent}`,
        "crop": "true"
      })
    };

    request(cropOptions, (cropError, cropResponse, cropBody) => {
      if (cropError) {
        console.error(cropError);
        res.status(500).json({ error: 'Something went wrong' });
      } else {
        const cropResponseData = JSON.parse(cropBody);
        if (cropResponseData.status === 'success') {
          const croppedImageUrl = cropResponseData.link;
          const { prompt } = req.body;
          const { strength } = req.body;

          const img2imgOptions = {
            method: 'POST',
            url: 'https://stablediffusionapi.com/api/v3/img2img',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              "key": "Z8g0l2PHJiazwGZchTwDF3TsEKOVd0QCJXaQ04pmDQK9UGqTAiAtkwy34mxh",
              prompt,
              "init_image": croppedImageUrl,
              negative_prompt: null,
              width: "512",
              height: "512",
              samples: "1",
              num_inference_steps: "20",
              seed: null,
              guidance_scale: 7.5,
              strength,
              safety_checker: "yes",
              multi_lingual: "no",
              panorama: "no",
              self_attention: "no",
              upscale: "no",
              embeddings_model: "embeddings_model_id",
              webhook: null,
              track_id: null
            })
          };

          request(img2imgOptions, (img2imgError, img2imgResponse, img2imgBody) => {
            if (img2imgError) {
              console.error(img2imgError);
              res.status(500).json({ error: 'Something went wrong' });
            } else {
              res.json(JSON.parse(img2imgBody));
            }
          });
        } else {
          res.status(500).json({ error: 'Crop API failed' });
        }
      }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong' });
  }
});

app.post('/api/download-image', async (req, res) => {
  try {
    const { imageUrl } = req.body;
    const response = await axios.get(imageUrl, {
      responseType: 'stream',
    });

    const imageName = `${uuidv4()}.png`;
    const imagePath = path.join(__dirname, 'downloads', imageName); // Modify the path to your desired directory for storing downloaded images

    const writer = fs.createWriteStream(imagePath);
    response.data.pipe(writer);

    writer.on('finish', () => {
      res.download(imagePath, imageName, (error) => {
        if (error) {
          console.error('Error downloading image:', error);
          res.status(500).json({ error: 'Something went wrong' });
        }
        // Delete the downloaded image file
        fs.unlinkSync(imagePath);
      });
    });

    writer.on('error', (error) => {
      console.error('Error downloading image:', error);
      res.status(500).json({ error: 'Something went wrong' });
    });
  } catch (error) {
    console.error('Error downloading image:', error);
    res.status(500).json({ error: 'Something went wrong' });
  }
});


app.post('/api/pix-pix', upload.single('image'), (req, res) => {
  try {
    const imagePath = req.file.path;
    const imageContent = fs.readFileSync(imagePath, { encoding: 'base64' });

    const cropOptions = {
      method: 'POST',
      url: 'https://stablediffusionapi.com/api/v3/base64_crop',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        "key": "Z8g0l2PHJiazwGZchTwDF3TsEKOVd0QCJXaQ04pmDQK9UGqTAiAtkwy34mxh",
        "image": `data:image/png;base64,${imageContent}`,
        "crop": "true"
      })
    };

    request(cropOptions, (cropError, cropResponse, cropBody) => {
      if (cropError) {
        console.error(cropError);
        res.status(500).json({ error: 'Something went wrong' });
      } else {
        const cropResponseData = JSON.parse(cropBody);
        if (cropResponseData.status === 'success') {
          const croppedImageUrl = cropResponseData.link;
          const { prompt } = req.body;

          const pix2pixOptions = {
            method: 'POST',
            url: 'https://stablediffusionapi.com/api/v5/pix2pix',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              "key": "Z8g0l2PHJiazwGZchTwDF3TsEKOVd0QCJXaQ04pmDQK9UGqTAiAtkwy34mxh",
              prompt,
              "init_image": croppedImageUrl,
              "prompt" : "make him woman",
              "image_guidance_scale" : 1,
              "steps" : 50,
              "guidance_scale" : 7
            })
          };

          request(pix2pixOptions, (pix2pixError, pix2pixResponse, pix2pixBody) => {
            if (pix2pixError) {
              console.error(pix2pixError);
              res.status(500).json({ error: 'Something went wrong' });
            } else {
              res.json(JSON.parse(pix2pixBody));
            }
          });
        } else {
          res.status(500).json({ error: 'Crop API failed' });
        }
      }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong' });
  }
});


app.post('/pix-pix', upload.single('image'), (req, res) => {
  try {
 
          const { prompt } = req.body;
          const { init_image } = req.body;

          const pix2pixOptions = {
            method: 'POST',
            url: 'https://stablediffusionapi.com/api/v5/pix2pix',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              "key": "Z8g0l2PHJiazwGZchTwDF3TsEKOVd0QCJXaQ04pmDQK9UGqTAiAtkwy34mxh",
              prompt,
              init_image,
              "image_guidance_scale" : 1,
              "steps" : 50,
              "guidance_scale" : 7
            })
          };

          request(pix2pixOptions, (pix2pixError, pix2pixResponse, pix2pixBody) => {
            if (pix2pixError) {
              console.error(pix2pixError);
              res.status(500).json({ error: 'Something went wrong' });
            } else {
              res.json(JSON.parse(pix2pixBody));
            }
          });
       
     

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong' });
  }
});


app.listen(5000, () => {
  console.log("Server Started");
});
