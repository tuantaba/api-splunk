#!/usr/bin/python
import urllib
import requests
import json
import time
import os


#Splunk config
baseurl = 'https://x.x.x.x:8089/services/search/jobs'
username = 'xxxxx'
password = 'xxxxxx'

def splunk_search(search_command):
    search = search_command
    output_mode = 'json'
    max_count = 100000
    auth = requests.auth.HTTPBasicAuth(username, password)
    data = {
        "search": search,
        "output_mode": output_mode,
        "max_count": max_count,
    }
    response = requests.post(baseurl, auth=auth, data=data, verify=False)

    if str(response.status_code) != '200' or str(response.status_code) != '201':
        print ("HTTP Request error, code", response.status_code)
        exit

    #print response.text
    job_id = json.loads(response.text)['sid']
    print "job id from splunk_running is: ", job_id
    # print response.text
    dispatchState = "UNKNOW"
    while dispatchState != "DONE" and dispatchState != "FAILED":
        response = requests.post(baseurl + "/" + job_id, data=data, auth=auth, verify=False)
        dispatchState = json.loads(response.text)['entry'][0]['content']['dispatchState']
        time.sleep(1)
        print "status dispatchState from splunk_running is:", dispatchState

    if dispatchState == "DONE":
        print "dispatchState is: ", dispatchState
        results_complete = False
        offset = 0
        results = list()
        while not results_complete:
            # data = {'output_mode': 'json'}
            response = requests.get(baseurl + "/" + job_id +
                                    '/results?count=50000&offset=' + str(offset),
                                    data=data, auth=auth, verify=False)
            json_load = json.loads(response.text)
            print len(json_load['results'])
            #print response.text
            results += json_load['results']
            if len(json_load['results']) == 0:  # This means that we got all of the results
                results_complete = True
            else:
                offset += 50000
#        print results
    else :
        print "state fail, exit..."
        return "failed"

    if len(results) == 0:
        print "=========================== No results"
        return "failed"
    return results

    # if 1 < len(results):
    #     raw_log.append(results[0]['_raw'])

    #    if 2 < len(results):
    #        raw_log.append(results[1]['_raw'])

    #    if 3 < len(results):
    #        raw_log.append(results[2]['_raw'])
    #    print "splunk_search: count_log is", count_log
    #    print raw_log
    # return raw_log
