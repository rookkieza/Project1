// CSP ไม่อนุญาต inline script จึงแยกไฟล์: ถามยืนยันก่อนลบ
document.querySelectorAll('form[data-confirm]').forEach(function (f) {
  f.addEventListener('submit', function (e) {
    if (!window.confirm(f.dataset.confirm)) e.preventDefault();
  });
});
