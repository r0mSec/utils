const tls = require('tls');
const fs = require('fs');
const { Client } = require('@elastic/elasticsearch')
const https = require('https');
const struct = require('python-struct');

var client = new Client(
    {
        node: 'http://elastic:xx@localhost:9200'
    });


function checkServerIdentity() {
    console.log("check server identity")
}


const options = {
    // Necessary only if using the client certificate authentication
    cert: fs.readFileSync('logstash/logstash.crt'),
    key: fs.readFileSync('logstash/logstash.key'),
    ca: fs.readFileSync('ca/ca.crt'),
    checkServerIdentity:checkServerIdentity

  };


console.log(options)



function sendCommand(host, cmd) {
    console.log("send command", host, cmd)
    var client = tls.connect(4242, host ,options, function() {

        // Check if the authorization worked
        if (client.authorized) {
            console.log("Connection authorized by a Certificate Authority.");
        } else {
            console.log("Connection not authorized: " + client.authorizationError)
        }

        // Send a friendly message
       var json = JSON.stringify(cmd)
       var header = struct.pack('>i',  [json.length] );
       console.log("send :", header)
       let jsize = (struct.unpack('>i', header)[0])

       let buffer = Buffer.concat([header, Buffer.from(json)])

       client.write(buffer, "binary")
    });

    let file = "filercv"
    let json = ""
    let datatype = undefined
    client.on( "connection", () => {
        console.log("onConnection says we have someone!");
    } );

    client.on("data", function(part) {
       if (datatype === undefined){
            jsize = (struct.unpack('>i', part)[0])
            part = part.slice(4)
            //console.log(JSON.stringify(part,null,2))
            datatype = 'json'
       }

       if (datatype == 'json')
            json = json + part
       if (datatype == 'file') {
            console.log('reveived new file part', part.length)
            fs.appendFileSync(file, part)
       }

       console.log(jsize, json.length )
       if (datatype == 'json' && json.length == jsize) {
            console.log("json file has been received", json.length)
            datatype = 'file'
            fs.writeFileSync(file, '')
        }
    });

    client.on('end', function() {
        let result = JSON.parse(json)
        console.error(result.code)
        console.log(result.time)
        console.log('\x1b[32m%s\x1b[0m', result.stdout);  //cyan

        console.log("\x1b[31m%s\x1b[0m", result.error)
        console.log("\x1b[33m%s\x1b[0m", result.fileError)

        console.log("Connection end");

    });


    client.on('close', function() {

        console.log("Connection closed");

    });

    // When an error ocoures, show it.
    client.on('error', function(error) {

        console.error(error);

        // Close the connection after the error occurred.
        client.destroy();

    });
}

async function bulkUpdate (bulkBody) {

    console.log("begin update")
    const response = await client.transport.request({
      method: 'POST',
      path: '_bulk',
      bulkBody: bulkBody, //[ { update: { _index: 'plop', _id : 1 } }, { doc : {"@timestamp" : "4"}}],
      querystring: {}
    })
    console.log("end update")

    console.log(response)
}

async function getCommand() {
    //console.log("new instance")
    let query = {
        "size": 100,
        "index": "cmd",
        "query": {
        "bool": {
          "must_not" : [
            {
              "exists": {
                "field": "ackTime"
              }
            }

          ] }
        }
      }


    let res = await client.search(query)
    if (!(res.hits.hits.length > 0)) {
        //console.log("no new command")
        return
    }

    let update = []
    res.hits.hits.forEach(x => {
        console.log(JSON.stringify(x,null,2))
        const {_id, _source : { data, id, host } } = x
        console.log(_id, data, id, host)
        update.push({ update: { _index: 'cmd', _id : _id } })
        update.push({ doc : {  "ackTime" : new Date()  } } )

        host.forEach(hostname => {
            sendCommand(hostname, {id : id, data : data})
        })
    })
    bulkUpdate(update)
}



var xml = `
<Sysmon schemaversion="4.81">
    <HashAlgorithms>sha256,IMPHASH</HashAlgorithms>
    <CheckRevocation/>
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <ProcessCreate onmatch="exclude">
                <Product condition="is">ForenSOC</Product>
            </ProcessCreate>
        </RuleGroup>
        <RuleGroup name="" groupRelation="or">
        <NetworkConnect  onmatch="exclude">
        </NetworkConnect >
    </RuleGroup>
    </EventFiltering>
</Sysmon>
`

var ntfsinfo = `
<ntfsinfo walker="MFT" resurrect="yes">
    <fileinfo>data\\fileinfo.csv</fileinfo>

    <location>%SystemDrive%\\Windows\\System32\\winevt\\Logs</location>
    <columns>
        <default>Default</default>
    </columns>
</ntfsinfo>
`
ntfsinfo = `<ntfsinfo walker="MFT">
<fileinfo>data\\fileinfo.csv</fileinfo>
<location>C:</location>
<columns>
<default>Default</default>
</columns>
</ntfsinfo>`



var gethive =`<?xml version="1.0"?>
<getthis reportall="" flushregistry="yes">
  <location>*</location>
  <samples MaxPerSampleBytes="500MB" MaxTotalBytes="2048MB">
    <sample>
      <ntfs_find name="ntuser.dat" header="regf" />
      <ntfs_find name="UsrClass.dat" header="regf" />
    </sample>
  </samples>
</getthis>`


let fastfind = `
<fastfind version="Test 2.0">
<filesystem>
    <location shadows="yes">C:</location>
    <yara source="./temp/FastFind.yar" block="2K" timeout="120" overlap="8192" scan_method="filemapping" />
    <ntfs_find  yara_rule="*" path_match="*xx*" />
</filesystem>
</fastfind>`

let yar = `
import "pe"

rule password {

    strings :
        $password = "password" nocase
    condition :
        $password
}
rule mdp {

    strings :
        $mdp = "mdp" nocase
    condition :
        $mdp
}
rule motdepasse {

    strings :
        $mot = "mot" nocase
        $pass = "pass" nocase
    condition :
        all of them
}

rule webshell {
    strings :
        $webshell = "WScript.Shell" nocase

    condition :
        $webshell
}

`


//yar = fs.readFileSync("concat.yara", "utf-8")
function scmd(id, computer) {
    console.log("command id is ============================================>", id)
    switch(id) {
    case 0 : sendCommand(computer, {id : 0, data : "temp"}); break;
    case 1 : sendCommand(computer, {id : 1, data : xml.toString() }); break;
    case 2 : sendCommand(computer, {id : 2, data : ntfsinfo.toString()}); break;
    case 3 : sendCommand(computer, {id : 3, data :''}); break;
    case 4 : sendCommand(computer, {id : 4, data :''}); break;
    case 5 : sendCommand(computer, {id : 5, data : gethive}); break;
    case 6 : sendCommand(computer, {id : 6, xml : fastfind, yar : yar}); break;
    case 7 : sendCommand(computer, {id : 7, location : "C:",
    orcpath : [
        "\\w\\test.asp",
    ]}); break;
    }
}


//sendCommand("machine", {id : 0, data : "temp"})
setInterval(getCommand, 1000)