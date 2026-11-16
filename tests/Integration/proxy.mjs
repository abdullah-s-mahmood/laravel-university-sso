import https from 'node:https';
import http from 'node:http';
import fs from 'node:fs';
const options={key:fs.readFileSync(process.env.TLS_KEY),cert:fs.readFileSync(process.env.TLS_CERT)};
for(const [port,target] of [[8443,8080],[3000,8000],[3001,8001],[3443,8002]]) {
  https.createServer(options,(req,res)=>{
    const upstream=http.request({host:'127.0.0.1',port:target,path:req.url,method:req.method,headers:{...req.headers,'x-forwarded-proto':'https','x-forwarded-for':'127.0.0.1'}},r=>{res.writeHead(r.statusCode,r.headers);r.pipe(res);});
    upstream.on('error',()=>{res.writeHead(503);res.end('upstream unavailable');});
    req.pipe(upstream);
  }).listen(port,'127.0.0.1');
}

https.createServer(options,(_req,res)=>{
  res.writeHead(200,{'content-type':'text/plain'});
  res.end('Native callback received');
}).listen(3002,'127.0.0.1');
