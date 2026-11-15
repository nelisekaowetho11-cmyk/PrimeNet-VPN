
PROTOCOL_FORM = r"""
<div class="card">
<h2>Manual Configuration</h2>

<label>Protocol</label>
<select id="proto" name="protocol" form="accountform"
onchange="buildFields()">
<option>VLESS</option>
<option>VMESS</option>
<option>TROJAN</option>
<option>SHADOWSOCKS</option>
</select>

<div id="fields"></div>
</div>

<script>
function field(label,name,type="text"){
 return `<label>${label}</label>
 <input name="${name}" type="${type}" form="accountform">`;
}

function select(label,name,items){
 return `<label>${label}</label>
 <select name="${name}" form="accountform">
 ${items.map(x=>`<option>${x}</option>`).join("")}
 </select>`;
}

function buildFields(){
 let p=document.getElementById("proto").value;
 let h="";

 h+=field("Server address","server");
 h+=field("Server port","port","number");

 if(p==="VLESS" || p==="VMESS"){
  h+=field("UUID","secret");

  if(p==="VLESS")
   h+=select("Flow","flow",["none","xtls-rprx-vision"]);
  else {
   h+=select("Alter ID","alterid",["0","1","16","32"]);
   h+=select("Encryption","encryption",["auto","none","zero"]);
  }

 }else if(p==="TROJAN"){
  h+=field("Trojan password","secret");

 }else{
  h+=select("Encryption method","method",[
   "aes-128-gcm",
   "aes-256-gcm",
   "chacha20-ietf-poly1305"
  ]);
  h+=field("Shadowsocks password","secret");
 }

 h+=select("Transport","transport",[
  "TCP","WebSocket","gRPC","HTTPUpgrade","XHTTP"
 ]);

 h+=`<div id="transportfields"></div>`;

 h+=select("Security","security",[
  "None","TLS","REALITY"
 ]);

 h+=`<div id="securityfields"></div>`;

 document.getElementById("fields").innerHTML=h;

 document.querySelector('[name=transport]')
  .onchange=transportFields;

 document.querySelector('[name=security]')
  .onchange=securityFields;

 transportFields();
 securityFields();
}

function transportFields(){
 let t=document.querySelector('[name=transport]').value;
 let h="";

 if(["WebSocket","HTTPUpgrade","XHTTP"].includes(t))
  h+=field("Path","path");

 if(t==="gRPC")
  h+=field("Service name","service_name");

 document.getElementById("transportfields").innerHTML=h;
}

function securityFields(){
 let s=document.querySelector('[name=security]').value;
 let h="";

 if(s==="TLS"){
  h+=field("SNI / Server name","sni");
  h+=field("TLS fingerprint","fingerprint");

 }else if(s==="REALITY"){
  h+=field("SNI","sni");
  h+=field("Public key","public_key");
  h+=field("Short ID","short_id");
  h+=field("Fingerprint","fingerprint");
 }

 document.getElementById("securityfields").innerHTML=h;
}

buildFields();
</script>
"""
