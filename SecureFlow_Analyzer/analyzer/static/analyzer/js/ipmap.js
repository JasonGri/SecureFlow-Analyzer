// IP GEOLOACTION MAPPING
var map = L.map("map").setView([51.505, -0.09], 13);

L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
  maxZoom: 19,
  minZoom: 3,
  attribution:
    '&copy; <a href="http://www.openstreetmap.org/copyright">OpenStreetMap</a><br><span>IP address data powered by <a href="https://ipinfo.io">IPinfo</a></span>',
}).addTo(map);

// Get coordinates for each ip through django's context
var ip_coords = JSON.parse(document.getElementById("coordinates").textContent);

const markers = [];
// Iterate through the coordinates and set markers
Object.entries(ip_coords).forEach(([ip, coord]) => {
  const lat = coord.split(",")[0];
  const long = coord.split(",")[1];

  var marker = L.marker([lat, long]).addTo(map);
  marker.bindPopup(`<b>${ip}</b>`);
  markers.push(marker);
});

// Zoom accordingly to include all markers
var group = new L.featureGroup(markers);
map.fitBounds(group.getBounds());
