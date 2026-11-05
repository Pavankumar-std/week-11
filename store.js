const fs=require('fs'),path=require('path');
const file=path.join(__dirname,'..','data','store.json');
function load(){if(!fs.existsSync(file))fs.writeFileSync(file,JSON.stringify({users:[],jobs:[],applications:[]}));return JSON.parse(fs.readFileSync(file,'utf8'));}
function save(data){fs.writeFileSync(file,JSON.stringify(data,null,2));}
module.exports={load,save};
