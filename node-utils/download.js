const request = require("request");
const fs = require("fs");

var args = process.argv.slice(2);
if (args.length != 3) {
  console.log("Usage: download.js DOWNLOAD_URL KEY OUTPUT_FILE");
  exit(1);
}

var downloadUrl = args[0];
var key = args[1];
var outputFile = args[2];

var out = fs.createWriteStream(outputFile);
var receivedBytes = 0;
var totalBytes = 0;

var progressHandle = setInterval(() => {
  var percentage = ((receivedBytes / totalBytes) * 100).toFixed(2);
  console.log(receivedBytes, totalBytes, `${percentage}%`);
}, 5000);

var req = request({
  method: "GET",
  uri: downloadUrl,
  headers: {
    Authorization: "Bearer " + key,
  },
});
req.pipe(out);
req.on("response", function (data) {
  totalBytes = parseInt(data.headers["content-length"]);
});
req.on("data", function (chunk) {
  receivedBytes += chunk.length;
});
req.on("end", function () {
  console.log("Download finished!");
  clearInterval(progressHandle);
});
