from elasticsearch import Elasticsearch
import json
import os
es = Elasticsearch(['http://elasticsearch1:9200'])
INDEX = "fscrawler_rest"


def es_delete(doc_id):
    exists = es.exists(index=INDEX, id=doc_id)
    if exists:
        es.delete(index=INDEX, id=doc_id)


def es_search(query, args):
    query = {
        "query": {
            "bool": {
                "must": {
                    "query_string": {
                        "query": '\"'+query.strip()+'\"'
                    },
                },
                "filter": [{"term": {"external.{}.keyword".format(i): args[i]}} for i in args]
            }
        }
    }
    # print json.dumps(query)
    res = es.search(index=INDEX, body=query)
    # print res
    # print("Got %d Hits:" % res['hits']['total'])
    result = []
    for hit in res['hits']['hits']:
        item = hit["_source"]['external']
        # print(item)
        item["file_path"] = os.path.join(item['parent_path'], item['file_name'])
        result.append(item)
        # print("%(file_name)s %(repo_id)s: %(parent_path)s" % hit["_source"]['external'])
    return result
    # raise ValueError('A very specific bad thing happened.')
