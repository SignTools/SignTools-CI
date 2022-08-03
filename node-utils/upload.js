const fs = require("fs");
const tus = require("tus-js-client");
const { exit } = require("process");
const path = require("path");

var args = process.argv.slice(2);
if (args.length != 3) {
  console.log("Usage: upload.js FILE_TO_UPLOAD ENDPOINT KEY");
  exit(1);
}

var inputFile = args[0];
var endpoint = args[1];
var key = args[2];

var file = fs.createReadStream(inputFile);
var uploadedBytes = 0;
var totalBytes = 0;

var progressHandle = setInterval(() => {
  var percentage = ((uploadedBytes / totalBytes) * 100).toFixed(2);
  console.log(uploadedBytes, totalBytes, `${percentage}%`);
}, 5000);

var options = {
  endpoint: endpoint,
  metadata: {
    filename: path.basename(inputFile),
  },
  headers: {
    Authorization: "Bearer " + key,
  },
  parallelUploads: 6,
  onError(err) {
    console.log(err.message);
    exit(2);
  },
  onProgress(bytesUploaded, bytesTotal) {
    totalBytes = bytesTotal;
    uploadedBytes = bytesUploaded;
  },
  onSuccess() {
    console.log("Upload finished!");
    clearInterval(progressHandle);
    fs.writeFile("file_id.txt", upload.url.split("/").pop(), (err) => {
      if (err) {
        console.log(err.message);
        exit(3);
      }
    });
  },
};

var upload = new tus.Upload(file, options);
upload.start();
