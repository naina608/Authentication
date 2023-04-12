const express=require("express");
const path=require("path");
const mongoose=require("mongoose");
const cookieParser=require("cookie-parser");
const jwt=require("jsonwebtoken");
const bcrypt=require("bcrypt");
mongoose.connect("mongodb://127.0.0.1:27017",{
    dbName:"backend",
}).then(()=>{
    console.log("database connected");
}).catch((e)=>{console.log(e)});

//SCHEMA
const userSchema=new mongoose.Schema({
    name:String,
    email:String,
    password: String,
});

//model
const User=mongoose.model("User",userSchema);//take name of model &schema
const app=express();

//middleware
app.use(express.static(path.join(path.resolve(),"public")));
app.use(express.urlencoded({extended:true}));

// use cookies
app.use(cookieParser());


//THESE ALL ARE API's

//setting up view engine
app.set("view engine","ejs");
const isAuthendication=async(req,res,next)=>{
    // console.log(req.cookies.token)
   const {token}= req.cookies;
   if(token){
        const decodedtoken=jwt.verify(token,"ssffdd");
        // console.log(decodedtoken);
        req.user=await User.findById(decodedtoken._id); 
       next();
   }
   else{
   res.redirect("/login");
   }
}
app.get("/",isAuthendication,(req,res)=>{
  
   res.render("logout",{name:req.user.name}); 
});
app.get("/register",(req,res)=>{
    res.render("register");
})
app.get("/login",(req,res)=>{
    res.render("login");
})
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
  
    let user = await User.findOne({ email });
  
    if (!user) return res.redirect("/register");
  
    const isMatch = await bcrypt.compare(password, user.password);
  
    if (!isMatch)
      return res.render("login", {email,message: "Incorrect Password" });
  
    const token = jwt.sign({ _id: user._id }, "ssffdd");
  
    res.cookie("token", token, {
      httpOnly: true,
      expires: new Date(Date.now() + 60 * 1000),
    });
    res.redirect("/");
});
app.post("/register", async (req, res) => {
    const { name, email, password } = req.body;
  
    let user = await User.findOne({ email });
    if (user) {
      return res.redirect("/login");
    }
    const hashedPassword = await bcrypt.hash(password, 10);
  
    user = await User.create({
      name,
      email,
      password: hashedPassword,
    });
  
    const token = jwt.sign({ _id: user._id }, "ssffdd");
  
    res.cookie("token", token, {
      httpOnly: true,
      expires: new Date(Date.now() + 60 * 1000),
    });
    res.redirect("/");
  });
app.get("/logout",(req,res)=>{
    res.cookie("token",null,{
        httpOnly:true,
        expires:new Date(Date.now()),
    });
    res.redirect("/");
})


app.listen(5000,()=>{
    console.log("server is working");
})