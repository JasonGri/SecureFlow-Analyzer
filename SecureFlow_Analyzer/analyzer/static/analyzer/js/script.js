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

// Advanced Button
const advancedBtn = document.getElementById("advanced-btn");
const caretUp = "http://127.0.0.1:8000/static/svgIcons/caret-up.svg";
const caretDown = "http://127.0.0.1:8000/static/svgIcons/caret-down.svg";

const varContainer = document.getElementById("variables-container");

if (advancedBtn) {
  advancedBtn.addEventListener("click", (e) => {
    varContainer.classList.toggle("hide");
    var imgSrc = advancedBtn.lastElementChild.src;
    if (imgSrc === caretUp) {
      advancedBtn.lastElementChild.src = caretDown;
    } else {
      advancedBtn.lastElementChild.src = caretUp;
    }
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

// Results elapsed time
const timeElapsed = document.getElementById("time-elapsed");

if (timeElapsed) {
  timeElapsed.textContent = formatDuration(
    parseFloat(timeElapsed.textContent) * 1000
  );
}

// VULNERABLE SERVICES
const serviceBtns = document.querySelectorAll(".service-btn");

serviceBtns.forEach((btn) => {
  btn.addEventListener("click", (e) => {
    e.target.classList.toggle("active");
  });
});

// Port Scans
const portsBtns = document.querySelectorAll(".port-btn");

portsBtns.forEach((btn) => {
  btn.addEventListener("click", (e) => {
    var clickedElement;
    if (e.target === btn) {
      clickedElement = e.target;
    } else {
      clickedElement = e.target.parentElement;
    }

    clickedElement.nextElementSibling.classList.toggle("hide");
    var imgSrc = clickedElement.lastElementChild.src;

    if (imgSrc === caretUp) {
      clickedElement.lastElementChild.src = caretDown;
    } else {
      clickedElement.lastElementChild.src = caretUp;
    }
  });
});

// HTTP Inspection
const httpBtns = document.querySelectorAll(".http-btn");

httpBtns.forEach((btn) => {
  btn.addEventListener("click", (e) => {
    e.target.classList.toggle("active");
  });
});
