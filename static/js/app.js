// Theme toggle with persistence
(function(){
  const root = document.documentElement;
  const key = "theme";
  const saved = localStorage.getItem(key);
  if(saved){ root.setAttribute("data-theme", saved); }
  document.getElementById("themeToggle")?.addEventListener("click", ()=>{
    const current = root.getAttribute("data-theme") || "dark";
    const next = current === "dark" ? "light" : "dark";
    root.setAttribute("data-theme", next);
    localStorage.setItem(key, next);
  });
})();
