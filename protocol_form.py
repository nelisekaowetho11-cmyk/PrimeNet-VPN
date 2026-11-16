
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
<input name="port" type="number" min="1" max="65535" required placeholder="443">

<div id="protocolfields"></div>

<div id="transportfields"></div>

<label>Security</label>
<select name="security" id="security" onchange="buildFields()">
<option value="None">None</option>
<option value="TLS">TLS</option>
<option value="REALITY">REALITY</option>
</select>

<div id="securityfields"></div>

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
${items.map(x=>`<option value="${x}">${x}</option>`).join("")}
</select>
`;

}

function buildFields(){

const p=document.getElementById("proto").value;
const t=document.getElementById("transport").value;
const s=document.getElementById("security").value;

let ph="";
let th="";
let sh="";


if(p==="VLESS"){

ph+=field("UUID","secret","Enter UUID");

ph+=field(
"Flow",
"flow",
"xtls-rprx-vision"
);

}


if(p==="VMESS"){

ph+=field("UUID","secret","Enter UUID");

ph+=selectField(
"Alter ID",
"alterid",
["0","1","16","32"]
);

ph+=selectField(
"Encryption",
"encryption",
["auto","none","zero"]
);

}


if(p==="TROJAN"){

ph+=field(
"Trojan password",
"secret",
"Enter password",
"password"
);

}


if(p==="SHADOWSOCKS"){

ph+=selectField(
"Encryption method",
"method",
[
"aes-128-gcm",
"aes-256-gcm",
"chacha20-ietf-poly1305",
"2022-blake3-aes-128-gcm",
"2022-blake3-aes-256-gcm"
]
);

ph+=field(
"Shadowsocks password",
"secret",
"Enter password",
"password"
);

}


if(
["WebSocket","HTTPUpgrade","XHTTP"].includes(t)
){

th+=field("Path","path","/");

th+=field(
"Host header",
"host",
"Optional host"
);

}


if(t==="gRPC"){

th+=field(
"Service name",
"service_name",
"Service name"
);

th+=selectField(
"gRPC mode",
"grpc_mode",
["gun","multi"]
);

}


if(t==="mKCP"){

th+=selectField(
"mKCP header",
"header_type",
[
"none",
"srtp",
"utp",
"wechat-video",
"dtls",
"wireguard"
]
);

th+=field(
"Seed",
"seed",
"Optional seed"
);

}


if(s==="TLS"){

sh+=field(
"SNI / Server name",
"sni",
"Optional SNI"
);

sh+=field(
"TLS fingerprint",
"fingerprint",
"chrome"
);

sh+=field(
"ALPN",
"alpn",
"h2,http/1.1"
);

}


if(s==="REALITY"){

sh+=field(
"SNI",
"sni",
"Server name"
);

sh+=field(
"Public key",
"public_key",
"Reality public key"
);

sh+=field(
"Short ID",
"short_id",
"Short ID"
);

sh+=field(
"Fingerprint",
"fingerprint",
"chrome"
);

sh+=field(
"SpiderX",
"spider_x",
"Optional SpiderX"
);

}


document.getElementById("protocolfields").innerHTML=ph;

document.getElementById("transportfields").innerHTML=th;

document.getElementById("securityfields").innerHTML=sh;

}

buildFields();

</script>
"""
