
PROTOCOL_FORM = r"""
<div class="card">
<h2>Xray Configuration</h2>

<label>Profile name</label>
<input name="profile_name" placeholder="My Private Account">

<label>Protocol</label>
<select name="protocol" id="proto" onchange="buildFields()">
<option value="VLESS">VLESS</option>
<option value="VMESS">VMess</option>
<option value="TROJAN">Trojan</option>
<option value="SHADOWSOCKS">Shadowsocks</option>
</select>

<label>Server address</label>
<input name="server" required placeholder="Server domain or IP">

<label>Port</label>
<input name="port" type="number" min="1" max="65535" required placeholder="443">

<div id="protocolfields"></div>

<label>Transport</label>
<select name="transport" id="transport" onchange="buildFields()">
<option value="">Choose transport</option>
<option value="TCP">TCP</option>
<option value="WebSocket">WebSocket</option>
<option value="gRPC">gRPC</option>
<option value="HTTPUpgrade">HTTPUpgrade</option>
<option value="XHTTP">XHTTP</option>
<option value="mKCP">mKCP</option>
</select>

<div id="transportfields"></div>

<label>Security</label>
<select name="security" id="security" onchange="buildFields()">
<option value="">Choose security</option>
<option value="None">None</option>
<option value="TLS">TLS</option>
<option value="REALITY">REALITY</option>
</select>

<div id="securityfields"></div>

<label>Mux</label>
<select name="mux_enabled" id="mux_enabled" onchange="buildFields()">
<option value="">Choose Mux setting</option>
<option value="false">Disable Mux</option>
<option value="true">Enable Mux</option>
</select>

<div id="muxfields"></div>

<label>HTTP Payload Proxy</label>
<select name="connection_mode" id="connection_mode" onchange="buildFields()">
<option value="Direct">Direct connection</option>
<option value="HTTP Payload Proxy">HTTP Payload Proxy</option>
</select>

<div id="proxyfields"></div>
</div>

<script>
function field(label,name,placeholder="",type="text"){
 return `
 <label>${label}</label>
 <input name="${name}" type="${type}" placeholder="${placeholder}">
 `;
}

function selectField(label,name,items){
 return `
 <label>${label}</label>
 <select name="${name}">
 <option value="">Choose ${label}</option>
 ${items.map(x=>`<option value="${x}">${x}</option>`).join("")}
 </select>
 `;
}

function buildFields(){
 const p=document.getElementById("proto").value;
 const t=document.getElementById("transport").value;
 const s=document.getElementById("security").value;
 const mux=document.getElementById("mux_enabled").value;
 const mode=document.getElementById("connection_mode").value;

 let ph="",th="",sh="",mf="",pr="";

 // Protocol-specific fields
 if(p==="VLESS"){
  ph+=field("UUID","secret","Enter UUID");
  ph+=field("Flow","flow","Optional flow");
 }

 if(p==="VMESS"){
  ph+=field("UUID","secret","Enter UUID");
  ph+=selectField("Alter ID","alterid",["0","1","16","32"]);
  ph+=selectField("Encryption","encryption",["auto","none","zero"]);
 }

 if(p==="TROJAN"){
  ph+=field("Trojan password","secret","Enter password","password");
 }

 if(p==="SHADOWSOCKS"){
  ph+=selectField("Encryption method","method",[
   "aes-128-gcm",
   "aes-256-gcm",
   "chacha20-ietf-poly1305",
   "2022-blake3-aes-128-gcm",
   "2022-blake3-aes-256-gcm"
  ]);
  ph+=field("Shadowsocks password","secret","Enter password","password");
 }

 // Transport-specific fields
 if(t==="TCP"){
  th+=selectField("TCP header type","header_type",["none","http"]);
 }

 if(["WebSocket","HTTPUpgrade","XHTTP"].includes(t)){
  th+=field("Path","path","/");
  th+=field("Host header","host","Optional host");
 }

 if(t==="gRPC"){
  th+=field("Service name","service_name","Service name");
  th+=selectField("gRPC mode","grpc_mode",["gun","multi"]);
 }

 if(t==="mKCP"){
  th+=selectField("mKCP header","header_type",[
   "none","srtp","utp","wechat-video","dtls","wireguard"
  ]);
  th+=field("Seed","seed","Optional seed");
 }

 // Security-specific fields
 if(s==="TLS"){
  sh+=field("SNI / Server name","sni","Optional server name");
  sh+=field("TLS fingerprint","fingerprint","chrome");
  sh+=field("ALPN","alpn","h2,http/1.1");
 }

 if(s==="REALITY"){
  sh+=field("SNI","sni","Server name");
  sh+=field("Public key","public_key","Reality public key");
  sh+=field("Short ID","short_id","Short ID");
  sh+=field("Fingerprint","fingerprint","chrome");
  sh+=field("SpiderX","spider_x","Optional SpiderX");
 }

 // Mux settings
 if(mux==="true"){
  mf+=`<h3>Mux Settings</h3>`;
  mf+=selectField("Mux protocol","mux_protocol",["smux","yamux"]);
  mf+=field("Mux concurrency","mux_concurrency","Example: 8","number");
 }

 // Optional HTTP payload proxy
 if(mode==="HTTP Payload Proxy"){
  pr+=`<h3>HTTP Proxy Settings</h3>`;
  pr+=field("HTTP proxy host","proxy_host","Proxy IP or domain");
  pr+=field("HTTP proxy port","proxy_port","8080","number");
  pr+=`
   <label>HTTP Payload</label>
   <textarea name="payload" rows="5"
   placeholder="Enter your HTTP payload here"></textarea>
  `;
 }

 document.getElementById("protocolfields").innerHTML=ph;
 document.getElementById("transportfields").innerHTML=th;
 document.getElementById("securityfields").innerHTML=sh;
 document.getElementById("muxfields").innerHTML=mf;
 document.getElementById("proxyfields").innerHTML=pr;
}

buildFields();
</script>
"""
