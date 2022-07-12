const { exit } = require("process");
const EasyDl = require("easydl");

var args = process.argv.slice(2);
if (args.length != 3) {
  console.log("Usage: download.js DOWNLOAD_URL KEY OUTPUT_FILE");
  exit(1);
}

var downloadUrl = args[0];
var key = args[1];
var outputFile = args[2];

var totalBytes = 0;

new EasyDl(downloadUrl, outputFile, {
  connections: 6,
  maxRetry: 5,
  httpOptions: {
    headers: {
      Authorization: "Bearer " + key,
    },
  },
})
  .on("metadata", function (metadata) {
    totalBytes = metadata.size;
  })
  .on("progress", function (data) {
    console.log(
      data.total.bytes,
      totalBytes,
      `${data.total.percentage.toFixed(2)}%`
    );
  })
  .on("error", function (err) {
    console.log(err.message);
    exit(3);
  })
  .on("end", function () {
    console.log("Download finished!");
  })
  .wait();
