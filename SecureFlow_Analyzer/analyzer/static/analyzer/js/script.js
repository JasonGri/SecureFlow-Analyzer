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

// Shorting of Conversations Table
// Formatting Bytes
function formatBytes(bytes) {
  if (bytes === 0) return "0 Bytes";

  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];

  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

// Formatting Duration
function formatDuration(milliseconds) {
  var seconds = Math.floor(milliseconds / 1000);
  var minutes = Math.floor(seconds / 60);
  var hours = Math.floor(minutes / 60);
  var days = Math.floor(hours / 24);

  if (days > 0) {
    return `${days}D ${hours % 24}h`;
  } else if (hours > 0) {
    return `${hours}h ${minutes % 60}min`;
  } else if (minutes > 0) {
    return `${minutes}min ${seconds % 60}sec`;
  } else if (seconds > 0) {
    return `${seconds}sec`;
  } else {
    return `${parseFloat(milliseconds).toFixed(2)}ms`;
  }
}
const convTable = new DataTable("#conversations-table", {
  columnDefs: [
    { orderable: false, targets: [1, 2, 3] },
    { orderable: true, targets: [0, 4, 5, 6] },
    {
      targets: 5,
      render: function (data, type) {
        if (type === "display") {
          return formatBytes(data);
        }
        return data;
      },
    },
    {
      targets: 6,
      render: function (data, type) {
        if (type === "display") {
          return formatDuration(data);
        }
        return data;
      },
    },
  ],
});

// Chart surrounding space
//TODO: Make it round

// VULNERABLE SERVICES
const serviceBtns = document.querySelectorAll(".service-btn");

serviceBtns.forEach((btn) => {
  btn.addEventListener("click", (e) => {
    e.target.classList.toggle("active");
  });
});

// Port Scans
const portScans = document.getElementById("scan-ports");
const portsBtn = document.getElementById("port-btn");

portsBtn.addEventListener("click", (e) => {
  portScans.classList.toggle("hide");
});
