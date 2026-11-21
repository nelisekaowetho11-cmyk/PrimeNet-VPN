
PROTOCOL_FORM = r"""
<div class="card">
  <h2>Server Configuration</h2>

  <label>Profile name</label>
  <input name="profile_name" placeholder="My PrimeNet server" required>

  <label>Protocol</label>
  <select name="protocol" id="proto" onchange="buildFields()" required>
    <option value="VLESS">VLESS</option>
    <option value="VMESS">VMess</option>
    <option value="TROJAN">Trojan</option>
    <option value="SHADOWSOCKS">Shadowsocks</option>
  </select>

  <label>Target server</label>
  <input name="server" placeholder="Domain or IP" required>

  <label>Port</label>
  <input name="port" type="number" min="1" max="65535"
         placeholder="443" required>

  <div id="protocolfields"></div>

  <div id="networkBlock">
    <label>Transport</label>
    <select name="transport" id="transport" onchange="buildFields()">
      <option value="tcp">TCP</option>
      <option value="ws">WebSocket</option>
      <option value="grpc">gRPC</option>
      <option value="httpupgrade">HTTPUpgrade</option>
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

  <div id="extraBlock">
    <h3>Additional Settings</h3>

    <label>Proxy IP / Host (optional)</label>
    <input name="proxy" placeholder="Example: 102.132.104.41">

    <label>Proxy Port (optional)</label>
    <input name="proxy_port" type="number"
           min="1" max="65535" value="8080"
           placeholder="8080">

    <label>Payload (optional)</label>
    <textarea name="payload" rows="4"
              placeholder="Enter your custom payload"></textarea>

    <label>Mux</label>
    <select name="mux" id="mux">
      <option value="false">Disable</option>
      <option value="true">Enable</option>
    </select>
  </div>
</div>

<script>
function inputField(label, name, placeholder="", type="text"){
  return `<label>${label}</label>
  <input name="${name}" type="${type}" placeholder="${placeholder}">`;
}

function selectField(label, name, items){
  return `<label>${label}</label>
  <select name="${name}">
    ${items.map(x =>
      `<option value="${x.value}">${x.label}</option>`
    ).join("")}
  </select>`;
}

function buildFields(){
  const p = document.getElementById("proto").value;
  const transport = document.getElementById("transport");
  const security = document.getElementById("security");

  let t = transport.value;
  let s = security.value;

  let pf = "";
  let tf = "";
  let sf = "";

  const ss = p === "SHADOWSOCKS";

  if(p === "VLESS"){
    pf += inputField("UUID", "secret", "VLESS UUID");
    pf += inputField(
      "Flow (optional)", "flow", "xtls-rprx-vision"
    );
  }

  if(p === "VMESS"){
    pf += inputField("UUID", "secret", "VMess UUID");

    pf += selectField("Alter ID", "alterid", [
      {value:"0",label:"0"},
      {value:"1",label:"1"},
      {value:"16",label:"16"},
      {value:"32",label:"32"}
    ]);

    pf += selectField("Encryption", "encryption", [
      {value:"auto",label:"auto"},
      {value:"none",label:"none"},
      {value:"zero",label:"zero"}
    ]);
  }

  if(p === "TROJAN"){
    pf += inputField(
      "Trojan Password", "secret", "Password", "password"
    );
  }

  if(ss){
    pf += selectField("Encryption Method", "method", [
      {value:"aes-128-gcm",label:"aes-128-gcm"},
      {value:"aes-256-gcm",label:"aes-256-gcm"},
      {value:"chacha20-ietf-poly1305",
       label:"chacha20-ietf-poly1305"},
      {value:"2022-blake3-aes-128-gcm",
       label:"2022-blake3-aes-128-gcm"},
      {value:"2022-blake3-aes-256-gcm",
       label:"2022-blake3-aes-256-gcm"}
    ]);

    pf += inputField(
      "Shadowsocks Password", "secret", "Password", "password"
    );
  }

  if(t === "ws" || t === "httpupgrade"){
    tf += inputField("Path", "path", "/");
    tf += inputField(
      "Host Header (optional)", "host", "Host name"
    );
  }

  if(t === "grpc"){
    tf += inputField(
      "gRPC Service Name", "service_name", "Service name"
    );

    tf += selectField("gRPC Mode", "grpc_mode", [
      {value:"gun",label:"gun"},
      {value:"multi",label:"multi"}
    ]);
  }

  if(s === "tls"){
    sf += inputField(
      "Server Name Indication (SNI)", "sni", "example.com"
    );

    sf += inputField(
      "TLS Fingerprint (optional)", "fingerprint", "chrome"
    );

    sf += inputField(
      "ALPN (optional)", "alpn", "h2,http/1.1"
    );
  }

  if(s === "reality"){
    sf += inputField(
      "Server Name Indication (SNI)", "sni", "example.com"
    );

    sf += inputField(
      "REALITY Public Key", "public_key", "Public key"
    );

    sf += inputField(
      "REALITY Short ID", "short_id", "Short ID"
    );

    sf += inputField(
      "Fingerprint", "fingerprint", "chrome"
    );

    sf += inputField(
      "SpiderX (optional)", "spider_x", "/"
    );
  }

  const realityOption = security.querySelector(
    'option[value="reality"]'
  );

  realityOption.disabled = p !== "VLESS";

  if(p !== "VLESS" && s === "reality"){
    security.value = "none";
    s = "none";
    sf = "";
  }

  document.getElementById("protocolfields").innerHTML = pf;
  document.getElementById("transportfields").innerHTML = tf;
  document.getElementById("securityfields").innerHTML = sf;

  document.getElementById("networkBlock").style.display =
    ss ? "none" : "block";

  document.getElementById("securityBlock").style.display =
    ss ? "none" : "block";

  if(ss){
    transport.value = "tcp";
    security.value = "none";
  }
}

buildFields();
</script>
"""
