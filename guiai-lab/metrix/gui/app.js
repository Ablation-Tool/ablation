(() => {
"use strict";
const token = document.body.dataset.token;
history.replaceState(null, "", location.pathname);
const fields = {format:"Format",architecture:"Architecture",artifact_class:"Class",status:"Inventory status",analysis_status:"Analysis status"};
const state = {query:"",sort:"path",ascending:true,filters:{}};
const selected = new Set();
const chatHistory = [];
let data = {summary:{},artifacts:[],agent:{configured:false}};
let visible = [];
let chatPending = false;
const body = document.getElementById("matrix-body");
const controls = document.getElementById("filter-controls");
const chatInput = document.getElementById("chat-input");
const chatSend = document.getElementById("chat-send");
function node(tag,text,className){const item=document.createElement(tag);if(text!==undefined)item.textContent=text;if(className)item.className=className;return item;}
async function api(path,options={}){
  const response = await fetch(path,{...options,headers:{...(options.headers||{}),"X-METRIX-Token":token}});
  const document = await response.json();
  if(!response.ok)throw new Error(document.error||`Request failed (${response.status})`);
  return document;
}
function badge(value){return node("span",value,`badge ${String(value).toLowerCase().replace(/[^a-z0-9]+/g,"-")}`);}
function humanSize(value){if(value===null||value===undefined)return "—";const units=["B","KiB","MiB","GiB","TiB"];let amount=Number(value);let index=0;while(amount>=1024&&index<units.length-1){amount/=1024;index++;}return `${index?amount.toFixed(amount>=10?1:2):amount} ${units[index]}`;}
function makeFilter(field,label){
  const wrapper=node("label");wrapper.append(node("span",label));
  const select=document.createElement("select");select.dataset.field=field;select.setAttribute("aria-label",label);
  select.append(new Option("All",""));
  const values=[...new Set(data.artifacts.map(record=>record[field]??"—"))].sort();
  values.forEach(value=>select.append(new Option(value,value)));
  select.addEventListener("change",()=>{state.filters[field]=select.value;render();});
  wrapper.append(select);controls.append(wrapper);
}
function detailRow(record){
  const row=node("tr",undefined,"details-row");row.hidden=true;
  const cell=document.createElement("td");cell.colSpan=9;
  const content=node("div",undefined,"details-content");
  const identity=node("section");identity.append(node("h2","Identity and provenance"));
  const identityList=document.createElement("dl");
  const root=String(data.summary.root||"").replace(/\/$/,"");
  [["Artifact ID",record.id],["Relative path",record.path],["Source path",`${root}/${record.path}`],["SHA256",record.sha256||"not available"],["Size bytes",record.size_bytes??"not available"],["Kind",record.kind],["Link target",record.link_target||"not applicable"]].forEach(([key,value])=>identityList.append(node("dt",key),node("dd",String(value))));
  identity.append(identityList);
  const detection=node("section");detection.append(node("h2","Detection and status"));
  const detectionList=document.createElement("dl");
  [["Format",record.format],["Architecture",record.architecture],["Endianness",record.endianness],["Artifact class",record.artifact_class],["Inventory status",record.status],["Analysis status",record.analysis_status],["Detection method",record.detection?.method||"not recorded"],["Detection evidence",record.detection?.evidence||"not recorded"],["Scan error",record.scan_error||"none"]].forEach(([key,value])=>detectionList.append(node("dt",key),node("dd",String(value))));
  detection.append(detectionList);content.append(identity,detection);cell.append(content);row.append(cell);return row;
}
function updateSelection(){
  document.getElementById("selection-count").textContent=`${selected.size} selected${selected.size>=25?" (limit reached)":""}`;
  document.getElementById("chat-context-count").textContent=`${selected.size} selected record${selected.size===1?"":"s"}`;
}
function toggleSelection(id,checked,checkbox){
  if(checked&&selected.size>=25&&!selected.has(id)){checkbox.checked=false;return;}
  if(checked)selected.add(id);else selected.delete(id);updateSelection();
}
function mainRow(record,detail){
  const row=document.createElement("tr");
  const selectCell=document.createElement("td");const checkbox=document.createElement("input");checkbox.type="checkbox";checkbox.checked=selected.has(record.id);checkbox.setAttribute("aria-label",`Select ${record.path}`);checkbox.addEventListener("change",()=>toggleSelection(record.id,checkbox.checked,checkbox));selectCell.append(checkbox);row.append(selectCell);
  row.append(node("td",record.path,"path"),node("td",record.format),node("td",record.architecture),node("td",record.artifact_class),node("td",humanSize(record.size_bytes)));
  row.append(node("td",record.sha256?`${record.sha256.slice(0,16)}…`:"—","hash"));
  const status=document.createElement("td");status.append(badge(record.status));row.append(status);
  const action=document.createElement("td");const button=node("button","Details","details-button");button.type="button";button.setAttribute("aria-expanded","false");
  button.addEventListener("click",()=>{detail.hidden=!detail.hidden;button.setAttribute("aria-expanded",String(!detail.hidden));button.textContent=detail.hidden?"Details":"Hide";});
  action.append(button);row.append(action);return row;
}
function render(){
  const terms=state.query.toLocaleLowerCase().split(/\s+/).filter(Boolean);
  visible=data.artifacts.filter(record=>{
    const haystack=JSON.stringify(record).toLocaleLowerCase();
    if(terms.some(term=>!haystack.includes(term)))return false;
    return Object.entries(state.filters).every(([field,value])=>!value||String(record[field]??"—")===value);
  });
  visible.sort((left,right)=>{
    let result;
    if(state.sort==="size_bytes"){
      if(left.size_bytes===null&&right.size_bytes===null)result=0;
      else if(left.size_bytes===null)return 1;
      else if(right.size_bytes===null)return -1;
      else result=left.size_bytes-right.size_bytes;
    }else result=String(left[state.sort]??"").localeCompare(String(right[state.sort]??""),undefined,{numeric:true});
    return(state.ascending?result:-result)||left.path.localeCompare(right.path);
  });
  body.replaceChildren();const fragment=document.createDocumentFragment();
  visible.forEach(record=>{const detail=detailRow(record);fragment.append(mainRow(record,detail),detail);});
  if(!visible.length){const row=document.createElement("tr");const cell=document.createElement("td");cell.colSpan=9;cell.textContent="No artifacts match the current filters.";row.append(cell);fragment.append(row);}
  body.append(fragment);document.getElementById("result-count").textContent=`${visible.length} of ${data.artifacts.length} artifacts`;
  updateSelection();
}
function applyAction(action){
  if(!action||action.type!=="filter")return;
  state.query=action.search||"";document.getElementById("query").value=state.query;
  Object.entries(action.filters||{}).forEach(([field,value])=>{
    if(!(field in fields))return;
    state.filters[field]=value;
    const select=controls.querySelector(`select[data-field="${field}"]`);
    if(select&&![...select.options].some(option=>option.value===value))select.append(new Option(value,value));
    if(select)select.value=value;
  });
  render();
  addMessage("system","Dashboard updated from the agent’s suggested filters.",false);
}
document.getElementById("query").addEventListener("input",event=>{state.query=event.target.value;render();});
document.getElementById("reset").addEventListener("click",()=>{state.query="";state.filters={};document.getElementById("query").value="";controls.querySelectorAll("select").forEach(select=>select.value="");render();});
document.getElementById("select-visible").addEventListener("click",()=>{for(const record of visible){if(selected.size>=25)break;selected.add(record.id);}render();});
document.getElementById("clear-selection").addEventListener("click",()=>{selected.clear();render();});
document.querySelectorAll("th button").forEach(button=>button.addEventListener("click",()=>{if(state.sort===button.dataset.sort)state.ascending=!state.ascending;else{state.sort=button.dataset.sort;state.ascending=true;}render();}));
document.getElementById("filters").addEventListener("submit",event=>event.preventDefault());
function csvCell(value){let text=typeof value==="object"&&value!==null?JSON.stringify(value):String(value??"");if(/^[=+\-@]/.test(text))text="'"+text;return '"'+text.replace(/"/g,'""')+'"';}
document.getElementById("export").addEventListener("click",()=>{
  const columns=["id","path","kind","size_bytes","sha256","format","architecture","endianness","artifact_class","status","analysis_status","detection","link_target","scan_error"];
  const lines=[columns.map(csvCell).join(",")];visible.forEach(record=>lines.push(columns.map(column=>csvCell(record[column])).join(",")));
  const blob=new Blob([lines.join("\r\n")+"\r\n"],{type:"text/csv;charset=utf-8"});const url=URL.createObjectURL(blob);const link=document.createElement("a");link.href=url;link.download="metrix-visible.csv";link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
});
function addMessage(role,content,recordHistory=true,details=""){
  const container=document.getElementById("chat-messages");
  if(chatHistory.length===0&&container.querySelector(".muted"))container.replaceChildren();
  const message=node("div",undefined,`message ${role}`);message.append(node("span",content));
  if(details){const disclosure=document.createElement("details");disclosure.append(node("summary","Raw bridge output"));disclosure.append(node("pre",details));message.append(disclosure);}
  container.append(message);container.scrollTop=container.scrollHeight;
  if(recordHistory&&(role==="user"||role==="assistant")){chatHistory.push({role,content});if(chatHistory.length>12)chatHistory.shift();}
}
function updateAgent(){
  const agent=data.agent;
  document.getElementById("agent-badge").textContent=agent.configured?`Agent bridge: ${agent.executable} (external CLI)`:"Agent bridge: disabled";
  const status=document.getElementById("agent-status");
  status.classList.toggle("offline",!agent.configured);
  status.textContent=agent.configured?`Connected command: ${agent.executable}. Request/response mode; no METRIX model or credentials are bundled.`:"No external agent configured. Restart with --agent kimi or --agent-command to enable chat.";
  document.getElementById("agent-details").textContent=JSON.stringify(agent,null,2);
  chatInput.disabled=!agent.configured;chatSend.disabled=!agent.configured||chatPending;
}
document.getElementById("chat-form").addEventListener("submit",async event=>{
  event.preventDefault();
  const message=chatInput.value.trim();if(!message||chatPending||!data.agent.configured)return;
  const previousHistory=chatHistory.map(item=>({...item}));
  addMessage("user",message);chatInput.value="";chatPending=true;chatSend.disabled=true;chatSend.textContent="Waiting for external CLI…";
  try{
    const response=await api("/api/chat",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({message,selected_ids:[...selected],filters:state.filters,search:state.query,history:previousHistory})});
    const raw=`${response.raw||""}${response.stderr?`\n[stderr]\n${response.stderr}`:""}`;
    addMessage("assistant",response.message,true,raw);
    if(response.warning)addMessage("system",response.warning,false);
    applyAction(response.action);
  }catch(error){addMessage("error",error.message,false);}finally{chatPending=false;chatSend.textContent="Send to external agent";updateAgent();}
});
chatInput.addEventListener("keydown",event=>{if((event.ctrlKey||event.metaKey)&&event.key==="Enter"){event.preventDefault();document.getElementById("chat-form").requestSubmit();}});
async function load(){
  try{
    data=await api("/api/state");
    document.getElementById("corpus-line").textContent=`${data.summary.artifacts} artifacts · ${data.summary.root} · METRIX ${data.summary.tool_version}`;
    Object.entries(fields).forEach(([field,label])=>makeFilter(field,label));
    updateAgent();render();
  }catch(error){document.getElementById("result-count").textContent=`Unable to load METRIX state: ${error.message}`;updateAgent();}
}
load();
})();
