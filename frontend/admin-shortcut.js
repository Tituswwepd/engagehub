// frontend/admin-shortcut.js
// Hidden keyboard shortcut: CTRL+SHIFT+A → open admin panel
document.addEventListener('keydown', e=>{
  if(e.ctrlKey && e.shiftKey && e.key.toLowerCase()==='a'){
    window.location.href='/admin.html';
  }
});
