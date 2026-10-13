const fs=require('fs');for(const file of ['index.html','style.css'])fs.copyFileSync('ui/'+file,'dist/'+file);

const version=JSON.parse(fs.readFileSync("src-tauri/tauri.conf.json","utf8")).version;fs.writeFileSync("dist/build-info.js",`window.__WINSETUP_VERSION__=${JSON.stringify(version)};\n`);
