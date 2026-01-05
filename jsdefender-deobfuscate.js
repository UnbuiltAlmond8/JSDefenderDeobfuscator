const fs = require('fs/promises');

async function readFile(filename) {
  try {
    const data = await fs.readFile(filename, 'utf8'); 
    return data;
  } catch (err) {
    console.error('Error reading file:', err);
  }
}

(async ()=>{
    const obfuscated = await readFile("jsdefender.js");
    _eval = eval;
    eval = function (code) {
        globalThis["layer2"] = code
        return _eval(code)
    };
    try {
        _eval(obfuscated);
    } catch {} finally {
        console.log(layer2)
    }
})()