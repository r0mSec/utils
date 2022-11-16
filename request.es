GET orc-*/_search
{
   "query":{
      "bool":{
         "must": [
          { "exists": { "field": "process.pe.original_file_name" } },
          { "exists": { "field": "file.name" } },
          { "term": { "file.extension.keyword" : "exe"         } }
          ],
          "must_not": [
            {  "wildcard": {"file.name.keyword": { "value": "*~*"      }    } },
            { "terms": { "file.name.keyword" :  [ "schtasks.exe" ]     } },
            {  "wildcard": {"file.directory.keyword": { "value": "*assembly*"      }    } }

          ], 
         "filter":[
            {
        "script": {
            "script": {
                "source": "doc['process.pe.original_file_name.keyword'].value.toLowerCase() != doc['file.name.keyword'].value.toLowerCase()",
                "lang": "painless"
            }
}
            }
         ]
      }
   },
   "track_total_hits": true
}

GET _search
{
  "query": {
    "bool": {
      "must": [
        {"term": {
          "type.keyword":  "computer"
          
        }}
      ]
    }
  }
}

POST _sql
{
  "query": "SELECT * FROM hash where positives != 0",
  "fetch_size": 10
}
post _sql
{
  "query" :"select * from hash"
}

delete virustotal
put virustotal
post virustotal/doc 
 {
    "scans": {

    "total": 53,
    "positives": 0,
    "sha256": "test",
    "md5": "f4a56c66efc6f4fcdd0f1d8f63fbb67d"
  }
}

get .enrich-*

GET virustotal/_search?q=*
PUT virustotal/_settings
{
  "index.default_pipeline": "set-id"
}


PUT _ingest/pipeline/set-id
{
  "processors": [
    {
      "set": {
        "field": "_id",
        "value": "{{scans.sha256}}"
      }
    }
  ]
}


delete   /_ingest/pipeline/procvt
delete  /_enrich/policy/vtpolicy

PUT /_enrich/policy/vtpolicy
{
"match": {
          "indices": "virustotal",
          "match_field": "scans.sha256",
          "enrich_fields": [ "scans.total", "scans.positives" ]
      }
}

put /_enrich/policy/vtpolicy/_execute

put  /_ingest/pipeline/procvt
{
            "description": "Vt checks",
           
            "processors": [
              {
                "enrich": {
                  "if": "ctx.winlog?.event_id == 1",
                  "policy_name": "vtpolicy",
                  "field": "process.hash.sha256",
                  "target_field": "virustotal",
                  "max_matches": "1"
                }
              }
            ]
          }


post  /_ingest/pipeline/procvt/_simulate
 { "docs": [
        {
          "_index": "logstash-*",
          "_id": "id",
          "_source": {
              "winlog" : { "event_id" : 1 },
             "process" : { "hash" : { "sha256" : "test" } }
            
          }
        }
      ]
    }







PUT logstash-*/_settings
{
  "index.default_pipeline": "_none"
}

get logstash-*/_search?q=1760709c83314b61da6cf357ac557137b829d1afcfcfcef947151889c9dab951

get logstash-*/_search 
{
  "query" : { 
    "bool": { 
      "must": [{
        "term": {"hash.sha256.keyword":"00bdc1b10c80806861a0dd913a382a34ff509acb25c2ec447f576e8417cb0db7"  }}
      ]}
    }
}


get hash/_search?q=11f02159cd9e001e9c8eb6ab3875132f77b9e9e8af981d45d182ec71ce68c5ad

GET hash/_search
{
  "size": 20,
  "_source": ["sha256", "total" , "positives", "@timestamp"], 
  "sort": [
    {
      "positives": {
        "order": "desc"
      }
    }
  ], 
  "query": {
      "bool": {
      "must": [
       { "exists": {"field": "positives"}},
       {"bool" : { "must_not": [ { "term": { "positives": 42 }}] } }
      ]
    }
  }
}

post _transform/hash/_stop
delete _transform/hash

post _transform/vt/_start
POST virustotal/_update/ZlYEW3JX9dwz8uptIRrvmEUAAAAAAAAA
{
  "doc": {
    "name": "kikou"
  }
}

get hash/_search?q=21.1.5827.0

get hash/_search
{
  "sort" : [{"types_count" : "desc"}],
  "query" : { 
    "bool": {
      "filter": [
        { 
          "range" : {
          "timestamp.max": { "gt": "2020-01-06T19:23:30.046"}
        }}
      ]
    }
  }
}

get hash/_search
{
  "query" : {
    "bool" : {
      "filter" : [{ 
        "exists": {  
          "field": "sha1"  
        }
      }
      ]
    }
  }
}
get hash/_search
{
    "size": 0,
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
}


get /forensoc/_doc/mRw8yYABRJUThEQShcA1
delete virustotal
post _transform/hash/_start


post _transform/_preview
{
  "source": {
    "index": "logstash-*",
     "query" : { "bool": {"filter" : [ {"terms" : {"winlog.event_id" : [1, 7, 15, 1002,  1004] }} ] }}
  },
  "dest" : { 
    "index" : "hash"
  },
  "sync" : { 
    "time": {
      "field": "@timestamp",
      "delay": "60s"
    }
  },
 
  "pivot": {
    "group_by": {  
      "sha256": { "terms": { "field": "hash.sha256.keyword" } }
      },
    "aggregations": {
      "timestamp.min": { "min": { "field": "@timestamp" }},
      "timestamp.max": { "max": { "field": "@timestamp" }},
      "launchCount" : { "value_count" : { "field" : "process.hash.sha256.keyword" } }

    }
  }
}


post orc/_doc/42
{
"file": {
    "directory": "\\Windows\\WinSxS\\wow64_microsoft-windows-wow64-legacy_31bf3856ad364e35_10.0.22000.653_none_f15acabd8d221703",
    "path": "\\Windows\\WinSxS\\wow64_microsoft-windows-wow64-legacy_31bf3856ad364e35_10.0.22000.653_none_f15acabd8d221703\\instnm.exe",
    "extension": "exe",
    "size": 9216,
    "attributes": "A....N.......",
    "timestamp": {
      "create" : "2021-06-05T12:05:55.420Z",
      "modif" : "2022-04-23T07:44:14.727Z",
      "delete" : "2022-05-10T18:00:58.699Z"
    }
  }
}


post orc/_doc/1
{
  "data" : 1,
  "process" : { "name" : "boudin" }
"attributes": "A....N.......",
}


delete orc
get orc-rve/_search 
{
  "size":0,
  "sort" : ["@timestamp" : "desc" ] ,
  "query" : {
    "bool" : {
      "filter" : [{ 
        "exists": {  
          "field": "datetype"  
        }
      }
      ]
    }
  }
}


PUT orc-*/_settings?preserve_existing=true
{
  "index.max_result_window" : 10000000
}



post cmd/_doc/42
{
  "host" : ["MAINTENANCE01.crgt-cluster.local"],
  "crTime" : "2022-05-22T08:34:38.445Z",
  "id" : 2, 
  "data" : ""
}

delete cmd

get cmd/_search








get _search/ 
{
  "from": 0,
  "size": 100,
  "query": {
                 "bool": {
                    "must": [
                      {
                        "term": {
                          "winlog.event_id": "1"
                        }
                      },
                      {
                        "bool": {
                          "must": [
                            {
                              "term": {
                                "process.name.keyword": "ProxySrv.exe"
                              }
                            }
                          ]
                        }
                      }
                    ]
                  }
                },
       
              ]
            }
          },
    
          {
            "range": {
              "@timestamp": {
                "lte": "now"
              }
            }
          }
        ]
      }
    }
  }
}





GET orc-crgt-webnet/_search 
{
    "query": {
    "bool" : {
    "must": [ 
      {    "term":  { "winlog.event_id": 1  } }
      ]
    }
}
}


POST /logstash-2022.06.11-000005/_delete_by_query
{
  "query": {
    "bool" : {
    "must": [ 
 
        {    "term":  {      "winlog.event_id": 26  } }


    ]
  }
  }
}














