const jwt=require('jsonwebtoken');
function auth(req,res,next){const h=req.headers.authorization||'';const token=h.startsWith('Bearer ')?h.slice(7):'';if(!token)return res.status(401).json({message:'Authentication required'});try{req.user=jwt.verify(token,process.env.JWT_SECRET);next();}catch{return res.status(401).json({message:'Invalid or expired token'});}}
function allow(...roles){return(req,res,next)=>roles.includes(req.user.role)?next():res.status(403).json({message:'Permission denied'});}
module.exports={auth,allow};
