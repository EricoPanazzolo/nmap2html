(function(){
  "use strict";
  const HOST_KEYS=Array.isArray(window.NMAP_REPORT_HOST_KEYS)?window.NMAP_REPORT_HOST_KEYS:[];
  const STORAGE_PREFIX="nmap-reviewed::";
  const storageKey=(hostKey)=>STORAGE_PREFIX+hostKey;
  function isReviewed(hostKey){try{return localStorage.getItem(storageKey(hostKey))==="1"}catch(_){return false}}
  function setReviewed(hostKey,reviewed){try{reviewed?localStorage.setItem(storageKey(hostKey),"1"):localStorage.removeItem(storageKey(hostKey))}catch(_){}}
  function updateReviewedCounter(){const count=HOST_KEYS.reduce((n,k)=>n+(isReviewed(k)?1:0),0);const el=document.getElementById("reviewed-counter");if(el)el.textContent=String(count)}
  function refreshReviewUI(hostKey){const reviewed=isReviewed(hostKey);const selector='[data-host-key="'+CSS.escape(hostKey)+'"]';document.querySelectorAll(selector).forEach(function(el){if(el.matches('[data-action="toggle-review"]')){el.classList.toggle("reviewed",reviewed);if(el.classList.contains("review-btn"))el.textContent=reviewed?"✓ Reviewed":"Mark as reviewed";el.setAttribute("aria-pressed",reviewed?"true":"false")}if(el.classList.contains("host-tab"))el.classList.toggle("reviewed",reviewed);if(el.tagName==="TR")el.classList.toggle("reviewed-row",reviewed)})}
  function refreshAllReviewUI(){HOST_KEYS.forEach(refreshReviewUI);updateReviewedCounter()}
  function toggleReviewed(hostKey){if(!hostKey)return;setReviewed(hostKey,!isReviewed(hostKey));refreshReviewUI(hostKey);updateReviewedCounter()}
  function switchView(view){const detail=document.getElementById("detail-view"),sheet=document.getElementById("sheet-view");if(!detail||!sheet)return;detail.classList.toggle("hidden",view!=="detail");sheet.classList.toggle("hidden",view!=="sheet");document.querySelectorAll('[data-action="switch-view"]').forEach(b=>b.classList.toggle("active",b.dataset.view===view))}
  function switchHost(index){const selected=String(index);document.querySelectorAll(".host-panel").forEach(p=>p.classList.toggle("hidden",p.dataset.hostIndex!==selected));document.querySelectorAll(".host-tab").forEach(t=>t.classList.toggle("active",t.dataset.hostIndex===selected))}
  function filterSheet(query){const q=query.trim().toLowerCase();document.querySelectorAll(".sheet-table tbody tr[data-search]").forEach(row=>row.classList.toggle("filtered-out",q!==""&&!(row.dataset.search||"").includes(q)))}
  document.addEventListener("click",function(event){
    const actionEl=event.target.closest("[data-action]");
    if(!actionEl)return;
    const action=actionEl.dataset.action;
    if(action==="switch-view"){switchView(actionEl.dataset.view||"detail");return}
    if(action==="switch-host"){if(event.target.closest("a"))return;switchHost(actionEl.dataset.hostIndex||"0");return}
    if(action==="toggle-review")toggleReviewed(actionEl.dataset.hostKey||"");
  });
  const search=document.getElementById("sheet-search");if(search)search.addEventListener("input",()=>filterSheet(search.value));
  refreshAllReviewUI();
})();
