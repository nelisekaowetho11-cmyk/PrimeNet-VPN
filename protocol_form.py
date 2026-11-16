
PROTOCOL_FORM = r"""
<div class="card">
<h2>Xray Configuration</h2>

<label>Profile name</label>
<input name="profile_name" placeholder="My Private Account">

<label>Connection mode</label>
<select name="connection_mode" id="connection_mode" onchange="buildFields()">
<option value="Direct">Direct</option>
<option value="HTTP Payload Proxy">HTTP Payload Proxy</option>
</select>

<label>Protocol</label>
<select name="protocol" id="proto" onchange="buildFields()">
<option value="VLESS">VLESS</option>
<option value="VMESS">VMess</option>
<option value="TROJAN">Trojan</option>
<option value="SHADOWSOCKS">Shadowsocks</option>
</select>

<label>Transport</label>
<select name="transport" id="transport" onchange="buildFields()">
<option value="TCP">TCP</option>
<option value="WebSocket">WebSocket</option>
<option value="gRPC">gRPC</option>
<option value="HTTPUpgrade">HTTPUpgrade</option>
<option value="XHTTP">XHTTP</option>
<option value="mKCP">mKCP</option>
</select>

<label>Server address</label>
<input name="server" required placeholder="Server domain or IP">

<label>Port</label>
<input name="port" type="number" required placeholder="443">

<div id="protocolfields"></div>
<div id="transportfields"></div>

<label>Security</label>
<select name="security" id="security" onchange="buildFields()">
<option value="None">None</option>
<option value="TLS">TLS</option>
<option value="REALITY">REALITY</option>
</select>

<div id="securityfields"></div>
<div id="proxyfields"></div>
</div>

<script>
function makeField(label,name,placeholder="",type="text"){
 return `<label>${label}</label>
 <input name="${name}" type="${type}" placeholder="${placeholder}">`;
}

function makeSelect(label,name,items){
 return `<label>${label}</label>
 <select name="${name}">
 ${items.map(x=>`<option value="${x}">${x}</option>`).join("")}
 </select>`;
}

function buildFields(){
 let p=document.getElementById("proto").value;
 let t=document.getElementById("transport").value;
 let s=document.getElementById("security").value;
 let mode=document.getElementById("connection_mode").value;

 let ph="";
 let th="";
 let sh="";
 let pr="";

 if(p==="VLESS"){
  ph+=makeField("UUID","secret","Enter UUID");
  ph+=makeField("Flow","flow","xtls-rprx-vision");
 }

 if(p==="VMESS"){
  ph+=makeField("UUID","secret","Enter UUID");
  ph+=makeSelect("Alter ID","alterid",["0","1","16","32"]);
  ph+=makeSelect("Encryption","encryption",["auto","none","zero"]);
 }

 if(p==="TROJAN"){
  ph+=makeField("Trojan password","secret","Enter password","password");
 }

 if(p==="SHADOWSOCKS"){
  ph+=makeSelect("Encryption method","method",[
   "aes-128-gcm",
   "aes-256-gcm",
   "chacha20-ietf-poly1305",
   "2022-blake3-aes-128-gcm",
   "2022-blake3-aes-256-gcm"
  ]);
  ph+=makeField("Shadowsocks password","secret","Enter password","password");
 }

 if(["WebSocket","HTTPUpgrade","XHTTP"].includes(t)){
  th+=makeField("Path","path","/");
  th+=makeField("Host header","host","Optional host");
 }

 if(t==="gRPC"){
  th+=makeField("Service name","service_name","Service name");
  th+=makeSelect("gRPC mode","grpc_mode",["gun","multi"]);
 }

 if(t==="mKCP"){
  th+=makeSelect("mKCP header","header_type",[
   "none","srtp","utp","wechat-video","dtls","wireguard"
  ]);
  th+=makeField("Seed","seed","Optional seed");
 }

 if(s==="TLS"){
  sh+=makeField("SNI / Server name","sni","Optional SNI");
  sh+=makeField("TLS fingerprint","fingerprint","chrome");
  sh+=makeField("ALPN","alpn","h2,http/1.1");
  sh+=`<label><input style="width:auto" type="checkbox" name="allow_insecure" value="yes"> Allow insecure certificates</label>`;
 }

 if(s==="REALITY"){
  sh+=makeField("SNI","sni","Server name");
  sh+=makeField("Public key","public_key","Reality public key");
  sh+=makeField("Short ID","short_id","Short ID");
  sh+=makeField("Fingerprint","fingerprint","chrome");
  sh+=makeField("SpiderX","spider_x","Optional SpiderX");
 }

 if(mode==="HTTP Payload Proxy"){
  pr+=`<h3>HTTP Proxy Settings</h3>`;
  pr+=makeField("HTTP proxy host","proxy_host","Proxy IP or domain");
  pr+=makeField("Proxy port","proxy_port","8080","number");
  pr+=`<label>HTTP payload (optional)</label>
  <textarea name="payload" placeholder="Paste your HTTP payload here"></textarea>`;
 }

 document.getElementById("protocolfields").innerHTML=ph;
 document.getElementById("transportfields").innerHTML=th;
 document.getElementById("securityfields").innerHTML=sh;
 document.getElementById("proxyfields").innerHTML=pr;
}

buildFields();
</script>
"""
