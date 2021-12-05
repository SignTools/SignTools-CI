const fs = require("fs");
const tus = require("tus-js-client");
const { exit } = require("process");
const path = require("path");

// modified from: https://github.com/tus/tus-js-client/blob/master/lib/node/sources/FileSource.js
class FileSource {
  constructor(stream) {
    this._stream = stream;
    this._path = stream.path.toString();
    this.size = stream.size ? stream.size : fs.statSync(this._path).size;
    this.offset = stream.start ? stream.start : 0;
  }
  slice(start, end) {
    const stream = fs.createReadStream(this._path, {
      start: start + this.offset,
      end: end - 1 + this.offset,
    });
    stream.size = end - start;
    return Promise.resolve({ value: stream });
  }
  close() {
    this._stream.destroy();
  }
}

class FileReader {
  openFile(input, chunkSize) {
    return Promise.resolve(new FileSource(input));
  }
}

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
  parallelUploads: 4,
  fileReader: new FileReader(),
  onError(error) {
    console.log(error.message);
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
        throw err;
      }
    });
  },
};

var upload = new tus.Upload(file, options);
upload.start();
