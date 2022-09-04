
const { Client } = require('@elastic/elasticsearch')
const https = require('https');
let auth = require('./authenString.json')
var client = new Client(
    {
        node: 'http://' + auth.name + ':' + auth.pass + '@' + auth.server + ':' + auth.port
    });


function getVt(hash) {
    let apikey = "xxx";
    const options = { method: 'GET' };
    https.get(`https://www.virustotal.com/vtapi/v2/file/report?resource=${hash}&apikey=${apikey}`, (resp) => {
        let data = '';
        // Un morceau de réponse est reçu
        resp.on('data', (chunk) => {
            data += chunk;
        });
        // La réponse complète à été reçue. On affiche le résultat.
        resp.on('end', () => {
            let scans = JSON.parse(data)
            console.log(scans);
            scans["@timestamp"] =  new Date()
            scans.sha256 = hash
            client.index({
                index : 'hash',
                body: scans
            })
        });
    }).on("error", (err) => {
        console.log("Error: " + err.message);
    });
}

//getVt("faacac7884db905abe2576b5098e8b946ecf02e24000a1c1f71ccefe9bb6a051")


async function searchNewHash() {
    console.log("new instance")
    let query = {
        "size": 10000,
        "index": "hash",
        "aggs": {
          "sha256": {
            "terms": {
              "field": "sha256"
            },
            "aggs": {
              
              "the_filter": {
                
                "bucket_selector": {
                  "buckets_path": {
                    "number": "_count"
                  },
                  "script": "params.number == 1"
                  
                }
              }
            }
          }
        }
      }



    let res = await client.search(query) 
    console.log(res.aggregations)
    let hash  = res.aggregations.sha256.buckets
    let len = Math.min(hash.length, 4)
    for(let i = 0; i < len ; i++ ) {
        console.log(hash[i].key)
        //getVt(hash[i].key)
    }
}


async function test() {
    
    try {
    let query = { query : "select sha256 from hash group by sha256 having(count(*) = 1) limit 10" } 
    //"fetch_size": 10

    let res = await client.sql.query(query) 
    let hash = res.rows
    let len = Math.min(hash.length, 4)
    console.log("new instance", len)
    for(let i = 0; i < len ; i++ ) {
        let sha = hash[i][0]
        console.log(sha)
        getVt(sha)
    }
  }
  catch (e) {
    console.log(e)
  }
}




async function get() {
  console.log("new instance")
  let query = {
      "size": 10000,
      "index": "hash",
      "query": {
        bool : { filter : [
          {
            "exists": {
              "field": "positives"
            }
          }
          
        ] }
    }
  }



  let res = await client.search(query) 
  
  let update = []
  res.hits.hits.forEach(x => {
    console.log(x)
    update.push({ update: { _index: 'hash', _id : x._id } })
    update.push({ doc : {"@timestamp" : new Date()}})
  })
  run(update)
  console.log(JSON.stringify(update,null,2))
}


async function run (bulkBody) {

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



//test()
setInterval(test, 1000 * 60)
//get()