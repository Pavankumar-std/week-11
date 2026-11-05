require('dotenv').config();
const express=require('express'),cors=require('cors'),helmet=require('helmet'),rateLimit=require('express-rate-limit'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),crypto=require('crypto');
const {body,validationResult}=require('express-validator'),{load,save}=require('./store'),{auth,allow}=require('./middleware');
if(!process.env.JWT_SECRET||process.env.JWT_SECRET.length<32)throw new Error('Set JWT_SECRET to a random value of 32+ characters');
const app=express();app.disable('x-powered-by');app.use(helmet());
const origins=(process.env.FRONTEND_URL||'http://127.0.0.1:5500').split(',').map(x=>x.trim());
app.use(cors({origin(o,cb){if(!o||origins.includes(o))return cb(null,true);cb(new Error('CORS origin not allowed'));},methods:['GET','POST','PATCH','DELETE'],allowedHeaders:['Content-Type','Authorization']}));
app.use(express.json({limit:'20kb'}));app.use(rateLimit({windowMs:15*60*1000,limit:100,standardHeaders:'draft-7',legacyHeaders:false}));
const loginLimit=rateLimit({windowMs:15*60*1000,limit:10,message:{message:'Too many login attempts. Try later.'}});
const validate=(req,res,next)=>{const e=validationResult(req);if(!e.isEmpty())return res.status(400).json({message:'Validation failed',errors:e.array()});next();};
app.get('/api/health',(req,res)=>res.json({status:'ok',service:'DG Job Portal API'}));
app.post('/api/auth/register',body('name').trim().isLength({min:2,max:60}),body('email').isEmail().normalizeEmail(),body('password').isLength({min:8,max:72}),body('role').isIn(['candidate','recruiter']),validate,async(req,res)=>{
 const db=load(),email=req.body.email.toLowerCase();if(db.users.some(u=>u.email===email))return res.status(409).json({message:'Email already registered'});
 const user={id:crypto.randomUUID(),name:req.body.name,email,password:await bcrypt.hash(req.body.password,12),role:req.body.role,createdAt:new Date().toISOString()};db.users.push(user);save(db);
 const token=jwt.sign({id:user.id,name:user.name,role:user.role},process.env.JWT_SECRET,{expiresIn:process.env.JWT_EXPIRES_IN||'2h'});
 res.status(201).json({token,user:{id:user.id,name:user.name,email:user.email,role:user.role}});
});
app.post('/api/auth/login',loginLimit,body('email').isEmail(),body('password').notEmpty(),validate,async(req,res)=>{
 const db=load(),u=db.users.find(x=>x.email===req.body.email.toLowerCase());if(!u||!(await bcrypt.compare(req.body.password,u.password)))return res.status(401).json({message:'Invalid email or password'});
 const token=jwt.sign({id:u.id,name:u.name,role:u.role},process.env.JWT_SECRET,{expiresIn:process.env.JWT_EXPIRES_IN||'2h'});res.json({token,user:{id:u.id,name:u.name,email:u.email,role:u.role}});
});
app.get('/api/jobs',(req,res)=>{const db=load(),page=Math.max(1,parseInt(req.query.page||'1',10)),limit=Math.min(20,Math.max(1,parseInt(req.query.limit||'5',10))),q=String(req.query.q||'').slice(0,80).toLowerCase();const all=db.jobs.filter(j=>`${j.title} ${j.company} ${j.location}`.toLowerCase().includes(q));res.json({data:all.slice((page-1)*limit,page*limit),page,limit,total:all.length,pages:Math.ceil(all.length/limit)});});
app.post('/api/jobs',auth,allow('recruiter','admin'),body('title').trim().isLength({min:3,max:100}),body('company').trim().isLength({min:2,max:80}),body('location').trim().isLength({min:2,max:80}),body('description').trim().isLength({min:10,max:2000}),validate,(req,res)=>{const db=load(),job={id:crypto.randomUUID(),...req.body,recruiterId:req.user.id,createdAt:new Date().toISOString()};db.jobs.unshift(job);save(db);res.status(201).json(job);});
app.post('/api/jobs/:id/apply',auth,allow('candidate'),(req,res)=>{const db=load();if(!db.jobs.some(j=>j.id===req.params.id))return res.status(404).json({message:'Job not found'});if(db.applications.some(a=>a.jobId===req.params.id&&a.candidateId===req.user.id))return res.status(409).json({message:'Already applied'});const a={id:crypto.randomUUID(),jobId:req.params.id,candidateId:req.user.id,status:'submitted',createdAt:new Date().toISOString()};db.applications.push(a);save(db);res.status(201).json(a);});
app.get('/api/me',auth,(req,res)=>res.json({user:req.user}));
app.use((err,req,res,next)=>{console.error(err.message);res.status(500).json({message:'Request could not be completed'});});
app.listen(process.env.PORT||5000,()=>console.log('API listening on '+(process.env.PORT||5000)));
