"use strict";

// Loading animation
const uploadBtn = document.getElementById("upload-btn");
const uploadBtnLoading = document.getElementById("upload-btn-loading");

if (uploadBtn) {
  uploadBtn.addEventListener("click", (e) => {
    uploadBtn.classList.add("visually-hidden");
    uploadBtnLoading.classList.remove("visually-hidden");
  });
}
