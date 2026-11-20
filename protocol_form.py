
PROTOCOL_FORM = r"""
<div class="card">
  <h2>Server Configuration</h2>

  <label>Profile name</label>
  <input name="profile_name" placeholder="My PrimeNet server">

  <label>Protocol</label>
  <select name="protocol" id="proto" onchange="buildFields()" required>
    <option value="VLESS">VLESS</option>
    <option value="TROJAN">Trojan</option>
    <option value="SHADOWSOCKS">Shadowsocks</option>
    <option value="VMESS">VMess</option>
  </select>

  <label>Server address</label>
  <input name="server" required placeholder="Server domain or IP">

  <label>Port</label>
  <input name="port" type="number" min="1" max="65535" required placeholder="443">

  <div id="protocolfields"></div>

  <div id="networkBlock">
    <label>Network</label>
    <select name="transport" id="transport" onchange="buildFields()">
      <option value="tcp">TCP</option>
      <option value="ws">WebSocket</option>
      <option value="grpc">gRPC</option>
      <option value="httpupgrade">HTTPUpgrade</option>
      <option value="xhttp">XHTTP</option>
      <option value="kcp">mKCP</option>
    </select>
    <div id="transportfields"></div>
  </div>

  <div id="securityBlock">
    <label>Security</label>
    <select name="security" id="security" onchange="buildFields()">
      <option value="none">None</option>
      <option value="tls">TLS</option>
      <option value="reality">REALITY</option>
    </select>
    <div id="securityfields"></div>
  </div>
</div>

<script>
function inputField(label,name,placeholder="",type="text"){
  return `<label>${label}</label>
  <input name="${name}" type="${type}" placeholder="${placeholder}">`;
}

function selectField(label,name,items){
  return `<label>${label}</label>
  <select name="${name}">
  ${items.map(x=>`<option value="${x.value}">${x.label}</option>`).join("")}
  </select>`;
}

function buildFields(){
  const p=document.getElementById("proto").value;
  const t=document.getElementById("transport").value;
  const s=document.getElementById("security").value;

  let pf="",tf="",sf="";

  if(p==="VLESS"){
    pf+=inputField("UUID","secret","VLESS UUID");
    pf+=inputField("Flow (optional)","flow","e.g. xtls-rprx-vision");
  }

  if(p==="TROJAN"){
    pf+=inputField("Trojan password","secret","Password","password");
  }

  if(p==="VMESS"){
    pf+=inputField("UUID","secret","VMess UUID");
    pf+=selectField("Alter ID","alterid",[
      {value:"0",label:"0"},
      {value:"1",label:"1"},
      {value:"16",label:"16"},
      {value:"32",label:"32"}
    ]);
    pf+=selectField("Encryption","encryption",[
      {value:"auto",label:"auto"},
      {value:"none",label:"none"},
      {value:"zero",label:"zero"}
    ]);
  }

  if(p==="SHADOWSOCKS"){
    pf+=selectField("Encryption method","method",[
      {value:"aes-128-gcm",label:"aes-128-gcm"},
      {value:"aes-256-gcm",label:"aes-256-gcm"},
      {value:"chacha20-ietf-poly1305",label:"chacha20-ietf-poly1305"},
      {value:"2022-blake3-aes-128-gcm",label:"2022-blake3-aes-128-gcm"},
      {value:"2022-blake3-aes-256-gcm",label:"2022-blake3-aes-256-gcm"}
    ]);
    pf+=inputField("Shadowsocks password","secret","Password","password");
  }

  if(["ws","httpupgrade","xhttp"].includes(t)){
    tf+=inputField("Path","path","/");
    tf+=inputField("Host header (optional)","host","Host name");
  }

  if(t==="grpc"){
    tf+=inputField("gRPC service name","service_name","Service name");
    tf+=selectField("gRPC mode","grpc_mode",[
      {value:"gun",label:"gun"},
      {value:"multi",label:"multi"}
    ]);
  }

  if(t==="kcp"){
    tf+=selectField("mKCP header","header_type",[
      {value:"none",label:"none"},
      {value:"srtp",label:"srtp"},
      {value:"utp",label:"utp"},
      {value:"wechat-video",label:"wechat-video"},
      {value:"dtls",label:"dtls"},
      {value:"wireguard",label:"wireguard"}
    ]);
    tf+=inputField("mKCP seed (optional)","seed","Seed");
  }

  if(t==="tcp"){
    tf+=selectField("TCP header type","header_type",[
      {value:"none",label:"none"},
      {value:"http",label:"http"}
    ]);
  }

  if(s==="tls"){
    sf+=inputField("Server name (SNI)","sni","example.com");
    sf+=inputField("TLS fingerprint (optional)","fingerprint","chrome");
    sf+=inputField("ALPN (optional)","alpn","h2,http/1.1");
  }

  if(s==="reality"){
    sf+=inputField("Server name (SNI)","sni","example.com");
    sf+=inputField("REALITY public key","public_key","Public key");
    sf+=inputField("REALITY short ID","short_id","Short ID");
    sf+=inputField("Fingerprint","fingerprint","chrome");
    sf+=inputField("SpiderX (optional)","spider_x","/");
  }

  const ss=(p==="SHADOWSOCKS");

  document.getElementById("networkBlock").style.display=ss?"none":"block";
  document.getElementById("securityBlock").style.display=ss?"none":"block";

  document.getElementById("protocolfields").innerHTML=pf;
  document.getElementById("transportfields").innerHTML=tf;
  document.getElementById("securityfields").innerHTML=sf;

  if(ss){
    document.getElementById("transport").value="tcp";
    document.getElementById("security").value="none";
  }
}

buildFields();
</script>
"""
